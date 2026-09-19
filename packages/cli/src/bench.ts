import fs from "node:fs/promises";
import path from "node:path";
import {
  computeMetrics,
  computeMetricsFromCounts,
  matchFindings,
  scanTarget,
  type BenchExpectation,
  type BenchMetrics
} from "@repo-auditor/scanner-core";
import type { AiProviderConfig, FetchLike } from "@repo-auditor/ai-review";
import type { CliIo } from "./index.js";

export interface BenchCase {
  name: string;
  target: string;
  expected: BenchExpectation[];
}

export interface BenchSpec {
  cases: BenchCase[];
}

export interface BenchAiOptions {
  provider: AiProviderConfig;
  maxTotalMs?: number;
}

export interface BenchAiAugmented {
  providerType: string;
  model: string;
  aiFindingsAdded: number;
  truncated: boolean;
  metrics: BenchMetrics;
}

export interface BenchCaseReport {
  name: string;
  target: string;
  expected: number;
  actual: number;
  matched: number;
  falsePositives: string[];
  falseNegatives: BenchExpectation[];
  metrics: BenchMetrics;
  aiAugmented?: BenchAiAugmented;
}

export interface BenchReport {
  generatedAt: string;
  cases: BenchCaseReport[];
  aggregate: BenchMetrics;
  aggregateAiAugmented?: BenchMetrics;
}

export async function loadBenchSpec(specPath: string): Promise<BenchSpec> {
  const raw = JSON.parse(await fs.readFile(specPath, "utf8")) as Partial<BenchSpec>;
  if (!raw || !Array.isArray(raw.cases) || raw.cases.length === 0) {
    throw new Error("Invalid benchmark spec: a non-empty cases array is required");
  }
  const specDir = path.dirname(path.resolve(specPath));
  return {
    cases: raw.cases.map((testCase) => ({
      name: String(testCase.name ?? "unnamed"),
      target: path.resolve(specDir, testCase.target),
      expected: Array.isArray(testCase.expected) ? testCase.expected : []
    }))
  };
}

export async function runBench(
  specPath: string,
  outputDir: string,
  io: CliIo,
  ai?: BenchAiOptions,
  fetchImpl?: FetchLike
): Promise<BenchReport> {
  const spec = await loadBenchSpec(specPath);
  const cases: BenchCaseReport[] = [];
  let tp = 0;
  let fp = 0;
  let fn = 0;
  let aiTp = 0;
  let aiFp = 0;
  let aiFn = 0;
  let aiCases = 0;

  for (const testCase of spec.cases) {
    const result = await scanTarget(testCase.target, {
      reviewMode: "full-audit",
      networkPolicy: "offline",
      outputFormats: ["json"]
    });
    const findings = result.report.findings;
    const match = matchFindings(findings, testCase.expected);
    const metrics = computeMetrics(match);
    tp += metrics.tp;
    fp += metrics.fp;
    fn += metrics.fn;

    const caseReport: BenchCaseReport = {
      name: testCase.name,
      target: testCase.target,
      expected: testCase.expected.length,
      actual: findings.length,
      matched: metrics.tp,
      falsePositives: match.falsePositives,
      falseNegatives: match.falseNegatives,
      metrics
    };

    if (ai) {
      const aiAugmented = await runAiAugmented(result.report, testCase.expected, ai, fetchImpl);
      if (aiAugmented) {
        aiTp += aiAugmented.metrics.tp;
        aiFp += aiAugmented.metrics.fp;
        aiFn += aiAugmented.metrics.fn;
        aiCases += 1;
        caseReport.aiAugmented = aiAugmented;
        io.writeOut(
          `  AI-augmented (${aiAugmented.model}): precision=${aiAugmented.metrics.precision.toFixed(2)} recall=${aiAugmented.metrics.recall.toFixed(2)} f1=${aiAugmented.metrics.f1.toFixed(2)} (+${aiAugmented.aiFindingsAdded} AI findings)\n`
        );
      }
    }

    cases.push(caseReport);

    io.writeOut(
      `${testCase.name}: precision=${metrics.precision.toFixed(2)} recall=${metrics.recall.toFixed(2)} f1=${metrics.f1.toFixed(2)} (TP ${metrics.tp}, FP ${metrics.fp}, FN ${metrics.fn})\n`
    );
  }

  const aggregate = computeMetricsFromCounts(tp, fp, fn);
  io.writeOut(
    `Aggregate: precision=${aggregate.precision.toFixed(2)} recall=${aggregate.recall.toFixed(2)} f1=${aggregate.f1.toFixed(2)} (TP ${tp}, FP ${fp}, FN ${fn})\n`
  );

  const report: BenchReport = {
    generatedAt: new Date().toISOString(),
    cases,
    aggregate
  };

  if (aiCases > 0) {
    report.aggregateAiAugmented = computeMetricsFromCounts(aiTp, aiFp, aiFn);
  }

  await fs.mkdir(outputDir, { recursive: true });
  await fs.writeFile(path.join(outputDir, "benchmark-report.json"), JSON.stringify(report, null, 2));
  await fs.writeFile(path.join(outputDir, "benchmark-report.md"), renderBenchMarkdown(report));

  return report;
}

async function runAiAugmented(
  report: Awaited<ReturnType<typeof scanTarget>>["report"],
  expected: BenchExpectation[],
  ai: BenchAiOptions,
  fetchImpl?: FetchLike
): Promise<BenchAiAugmented | undefined> {
  let mod: typeof import("@repo-auditor/ai-review");
  try {
    mod = await import("@repo-auditor/ai-review");
  } catch {
    return undefined;
  }

  let aiResult;
  try {
    aiResult = await mod.runAiReview(
      report,
      ai.provider,
      { scanPath: report.target.localPath ?? undefined, maxTotalMs: ai.maxTotalMs ?? 300_000 },
      fetchImpl
    );
  } catch {
    return undefined;
  }

  const merged = mod.mergeAiFindingsIntoReport(report, aiResult);
  const match = matchFindings(merged.findings, expected);
  const metrics = computeMetrics(match);

  return {
    providerType: ai.provider.type,
    model: ai.provider.model,
    aiFindingsAdded: aiResult.newFindings.length,
    truncated: Boolean(aiResult.truncated),
    metrics
  };
}

function fmt(n: number): string {
  return n.toFixed(2);
}

export function renderBenchMarkdown(report: BenchReport): string {
  const hasAi = report.cases.some((c) => c.aiAugmented);
  const lines: string[] = [
    "# Benchmark Report",
    "",
    `- Generated: ${report.generatedAt}`,
    "",
    "| Case | Expected | Actual | Matched | FP | FN | Precision | Recall | F1 |",
    "|------|----------|--------|---------|----|----|-----------|--------|----|"
  ];

  for (const testCase of report.cases) {
    lines.push(
      `| ${testCase.name} | ${testCase.expected} | ${testCase.actual} | ${testCase.matched} | ${testCase.metrics.fp} | ${testCase.metrics.fn} | ${fmt(testCase.metrics.precision)} | ${fmt(testCase.metrics.recall)} | ${fmt(testCase.metrics.f1)} |`
    );
    if (hasAi) {
      const ai = testCase.aiAugmented;
      const cell = ai
        ? `${fmt(ai.metrics.precision)} / ${fmt(ai.metrics.recall)} / ${fmt(ai.metrics.f1)} (+${ai.aiFindingsAdded})`
        : "(n/a)";
      lines.push(`| ${testCase.name} — AI-augmented | | | | | | ${cell.split(" / ")[0]} | ${cell.split(" / ")[1]} | ${ai ? cell.split(" / ")[2] : "(n/a)"} |`);
    }
  }

  lines.push(
    "",
    `**Aggregate**: Precision ${fmt(report.aggregate.precision)}, Recall ${fmt(report.aggregate.recall)}, F1 ${fmt(report.aggregate.f1)} (TP ${report.aggregate.tp}, FP ${report.aggregate.fp}, FN ${report.aggregate.fn})`
  );

  if (report.aggregateAiAugmented) {
    const ai = report.aggregateAiAugmented;
    lines.push(`**Aggregate AI-augmented**: Precision ${fmt(ai.precision)}, Recall ${fmt(ai.recall)}, F1 ${fmt(ai.f1)} (TP ${ai.tp}, FP ${ai.fp}, FN ${ai.fn})`);
  }

  lines.push(
    "",
    "## Details",
    ""
  );

  for (const testCase of report.cases) {
    lines.push(`### ${testCase.name}`, "", `- target: ${testCase.target}`);
    lines.push(
      `- false positives: ${testCase.falsePositives.length > 0 ? testCase.falsePositives.join(", ") : "(none)"}`
    );
    lines.push(
      `- false negatives: ${
        testCase.falseNegatives.length > 0
          ? testCase.falseNegatives
              .map((e) => `${e.category} @ ${e.filePath}${e.lineStart !== undefined ? `:${e.lineStart}` : ""}`)
              .join(", ")
          : "(none)"
      }`
    );
    if (testCase.aiAugmented) {
      lines.push(
        `- AI-augmented (${testCase.aiAugmented.model}): +${testCase.aiAugmented.aiFindingsAdded} AI findings${testCase.aiAugmented.truncated ? " (truncated)" : ""}`
      );
    }
    lines.push("");
  }

  return lines.join("\n") + "\n";
}
