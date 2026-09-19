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
import type { CliIo } from "./index.js";

export interface BenchCase {
  name: string;
  target: string;
  expected: BenchExpectation[];
}

export interface BenchSpec {
  cases: BenchCase[];
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
}

export interface BenchReport {
  generatedAt: string;
  cases: BenchCaseReport[];
  aggregate: BenchMetrics;
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

export async function runBench(specPath: string, outputDir: string, io: CliIo): Promise<BenchReport> {
  const spec = await loadBenchSpec(specPath);
  const cases: BenchCaseReport[] = [];
  let tp = 0;
  let fp = 0;
  let fn = 0;

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

    cases.push({
      name: testCase.name,
      target: testCase.target,
      expected: testCase.expected.length,
      actual: findings.length,
      matched: metrics.tp,
      falsePositives: match.falsePositives,
      falseNegatives: match.falseNegatives,
      metrics
    });

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

  await fs.mkdir(outputDir, { recursive: true });
  await fs.writeFile(path.join(outputDir, "benchmark-report.json"), JSON.stringify(report, null, 2));
  await fs.writeFile(path.join(outputDir, "benchmark-report.md"), renderBenchMarkdown(report));

  return report;
}

function fmt(n: number): string {
  return n.toFixed(2);
}

export function renderBenchMarkdown(report: BenchReport): string {
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
  }

  lines.push(
    "",
    `**Aggregate**: Precision ${fmt(report.aggregate.precision)}, Recall ${fmt(report.aggregate.recall)}, F1 ${fmt(report.aggregate.f1)} (TP ${report.aggregate.tp}, FP ${report.aggregate.fp}, FN ${report.aggregate.fn})`,
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
      }`,
      ""
    );
  }

  return lines.join("\n") + "\n";
}
