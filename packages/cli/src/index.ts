#!/usr/bin/env node
import fs from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { Command } from "commander";
import { scanTarget, type OutputFormat } from "@repo-auditor/scanner-core";

const outputFiles: Record<OutputFormat | "decision" | "remediation", string> = {
  html: "report.html",
  pdf: "report.pdf",
  markdown: "report.md",
  json: "findings.json",
  mermaid: "data-flow.mmd",
  sarif: "results.sarif",
  decision: "decision-record.json",
  remediation: "remediation-list.json"
};

export interface CliIo {
  writeOut: (value: string) => void;
  setExitCode: (code: number) => void;
}

const defaultIo: CliIo = {
  writeOut: (value) => process.stdout.write(value),
  setExitCode: (code) => {
    process.exitCode = code;
  }
};

export function createProgram(io: CliIo = defaultIo): Command {
  const program = new Command();

  program
    .name("repo-auditor")
    .description("Audit repositories and packages for suspicious security behavior")
    .version("0.1.0");

  program
    .command("scan")
    .argument("<target>")
    .option("--offline", "scan only local targets")
    .option("--no-network", "reject remote acquisition")
    .option("--output <dir>", "output directory", "reports/latest")
    .option("--format <formats>", "comma-separated formats", "markdown,json,mermaid")
    .action(async (target: string, flags: { offline?: boolean; network?: boolean; output: string; format: string }) => {
      const outputFormats = parseOutputFormats(flags.format);
      const networkPolicy = flags.offline ? "offline" : flags.network === false ? "no-network" : "online";
      const result = await scanTarget(target, {
        reviewMode: "full-audit",
        networkPolicy,
        outputFormats
      });

      if (result.outputs.pdf && outputFormats.includes("pdf")) {
        io.writeOut("Warning: PDF format requires Electron desktop app; outputting HTML as report.html instead.\n");
        result.outputs.html = result.outputs.pdf;
        delete result.outputs.pdf;
      }

      await fs.mkdir(flags.output, { recursive: true });

      for (const [name, content] of Object.entries(result.outputs)) {
        if (content === undefined) {
          continue;
        }

        await fs.writeFile(path.join(flags.output, outputFiles[name as keyof typeof outputFiles]), content);
      }

      io.writeOut(`Decision: ${result.report.risk.decision}\n`);
      io.writeOut(`Overall Risk: ${result.report.risk.overallRiskLevel}\n`);
      io.writeOut(`Report: ${path.resolve(flags.output, outputFiles.markdown)}\n`);

      if (result.report.risk.decision === "Block") {
        io.setExitCode(2);
      }
    });

  program
    .command("bench")
    .description("Measure scanner precision/recall against a hand-labeled benchmark spec")
    .option("--spec <path>", "benchmark spec file", "benchmarks/benchmarks.json")
    .option("--output <dir>", "output directory", "reports/bench")
    .option("--ai <type>", "enable AI-augmented benchmarking (cloud|ollama|custom)")
    .option("--ai-url <url>", "AI provider base URL")
    .option("--ai-model <model>", "AI model name")
    .option("--ai-key <key>", "AI API key (or REPO_AUDITOR_AI_KEY env var)")
    .action(async (flags: { spec: string; output: string; ai?: string; aiUrl?: string; aiModel?: string; aiKey?: string }) => {
      const { runBench } = await import("./bench.js");
      const aiOptions = flags.ai
        ? buildBenchAiOptions({ ai: flags.ai, aiUrl: flags.aiUrl, aiModel: flags.aiModel, aiKey: flags.aiKey })
        : undefined;
      await runBench(flags.spec, flags.output, io, aiOptions);
    });

  return program;
}

export async function runCli(argv: string[] = process.argv): Promise<void> {
  await createProgram().parseAsync(argv);
}

function parseOutputFormats(value: string): OutputFormat[] {
  const formats = value.split(",").map((format) => format.trim()).filter(Boolean);
  const allowed = new Set<OutputFormat>(["markdown", "json", "mermaid", "sarif", "html", "pdf"]);
  const invalid = formats.filter((format) => !allowed.has(format as OutputFormat));

  if (invalid.length > 0) {
    throw new Error(`Unsupported output format: ${invalid.join(", ")}`);
  }

  return formats as OutputFormat[];
}

function buildBenchAiOptions(flags: { ai: string; aiUrl?: string; aiModel?: string; aiKey?: string }): import("./bench.js").BenchAiOptions {
  const type = flags.ai;
  if (!["cloud", "ollama", "custom"].includes(type)) {
    throw new Error(`Unsupported AI provider type: ${type}`);
  }
  const defaultUrl = type === "ollama" ? "http://localhost:11434/v1" : "https://api.openai.com/v1";
  const defaultModel = type === "ollama" ? "llama3.2" : "gpt-4o-mini";
  const apiKey = flags.aiKey ?? process.env.REPO_AUDITOR_AI_KEY;
  return {
    provider: {
      type: type as import("@repo-auditor/ai-review").AiProviderType,
      baseUrl: flags.aiUrl ?? defaultUrl,
      model: flags.aiModel ?? defaultModel,
      apiKey: apiKey || undefined,
      dataSharingMode: "finding-snippets",
      redactionEnabled: true,
      timeoutMs: 120000,
      retryLimit: 1
    }
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await runCli();
}
