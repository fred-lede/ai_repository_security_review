import { describe, expect, it } from "vitest";
import type { Finding } from "../src/types.js";
import { computeMetrics, matchFindings, type BenchExpectation } from "../src/benchmark.js";

function finding(id: string, category: string, filePath: string, lineStart: number, lineEnd = lineStart): Finding {
  return {
    id,
    riskLevel: "High",
    category: category as Finding["category"],
    filePath,
    lineStart,
    lineEnd,
    codeSnippet: "x",
    explanation: "e",
    recommendedFix: "f",
    evidenceTags: [],
    confidence: "High"
  };
}

const exp = (category: string, filePath: string, lineStart?: number, lineEnd?: number): BenchExpectation =>
  lineStart === undefined ? { category, filePath } : { category, filePath, lineStart, lineEnd };

describe("matchFindings", () => {
  it("matches on category and filePath", () => {
    const result = matchFindings([finding("a", "network", "src/x.ts", 5)], [exp("network", "src/x.ts")]);
    expect(result.truePositives).toEqual([{ expectation: exp("network", "src/x.ts"), findingId: "a" }]);
    expect(result.falsePositives).toEqual([]);
    expect(result.falseNegatives).toEqual([]);
  });

  it("matches when line ranges overlap", () => {
    const result = matchFindings([finding("a", "network", "src/x.ts", 12, 14)], [exp("network", "src/x.ts", 13, 13)]);
    expect(result.truePositives).toHaveLength(1);
  });

  it("does not match disjoint line ranges", () => {
    const result = matchFindings([finding("a", "network", "src/x.ts", 15)], [exp("network", "src/x.ts", 13, 13)]);
    expect(result.truePositives).toEqual([]);
    expect(result.falsePositives).toEqual(["a"]);
    expect(result.falseNegatives).toEqual([exp("network", "src/x.ts", 13, 13)]);
  });

  it("matches file-level expectations without line numbers on any finding in that file", () => {
    const result = matchFindings([finding("a", "postinstall-script", "package.json", 7)], [exp("postinstall-script", "package.json")]);
    expect(result.truePositives).toHaveLength(1);
  });

  it("does not match across different categories or files", () => {
    const result = matchFindings(
      [finding("a", "network", "src/x.ts", 1), finding("b", "network", "src/y.ts", 1)],
      [exp("phishing", "src/x.ts", 1), exp("network", "src/z.ts", 1)]
    );
    expect(result.truePositives).toEqual([]);
    expect(result.falsePositives).toEqual(["a", "b"]);
    expect(result.falseNegatives).toHaveLength(2);
  });

  it("satisfies each expectation with at most one finding", () => {
    const result = matchFindings(
      [finding("a", "network", "src/x.ts", 1), finding("b", "network", "src/x.ts", 2)],
      [exp("network", "src/x.ts", 1)]
    );
    expect(result.truePositives).toEqual([{ expectation: exp("network", "src/x.ts", 1), findingId: "a" }]);
    expect(result.falsePositives).toEqual(["b"]);
  });
});

describe("computeMetrics", () => {
  it("computes perfect metrics on a full match", () => {
    const result = matchFindings([finding("a", "network", "src/x.ts", 1)], [exp("network", "src/x.ts", 1)]);
    const metrics = computeMetrics(result);
    expect(metrics).toEqual({ tp: 1, fp: 0, fn: 0, precision: 1, recall: 1, f1: 1 });
  });

  it("computes precision below 1 with false positives", () => {
    const result = matchFindings(
      [finding("a", "network", "src/x.ts", 1), finding("b", "network", "src/x.ts", 9)],
      [exp("network", "src/x.ts", 1)]
    );
    const metrics = computeMetrics(result);
    expect(metrics.tp).toBe(1);
    expect(metrics.fp).toBe(1);
    expect(metrics.precision).toBe(0.5);
    expect(metrics.recall).toBe(1);
  });

  it("treats nothing expected and nothing found as vacuous-perfect", () => {
    const metrics = computeMetrics(matchFindings([], []));
    expect(metrics).toEqual({ tp: 0, fp: 0, fn: 0, precision: 1, recall: 1, f1: 1 });
  });

  it("scores recall 0 when nothing is found", () => {
    const metrics = computeMetrics(matchFindings([], [exp("network", "src/x.ts", 1)]));
    expect(metrics).toEqual({ tp: 0, fp: 0, fn: 1, precision: 1, recall: 0, f1: 0 });
  });
});
