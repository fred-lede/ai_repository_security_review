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

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await runCli();
}
