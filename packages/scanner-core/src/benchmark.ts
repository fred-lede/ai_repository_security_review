import type { Finding } from "./types.js";

export interface BenchExpectation {
  category: string;
  filePath: string;
  lineStart?: number;
  lineEnd?: number;
}

export interface BenchMatch {
  expectation: BenchExpectation;
  findingId: string;
}

export interface BenchMatchResult {
  truePositives: BenchMatch[];
  falsePositives: string[];
  falseNegatives: BenchExpectation[];
}

export interface BenchMetrics {
  tp: number;
  fp: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
}

function rangesOverlap(
  findingStart: number,
  findingEnd: number,
  expStart: number,
  expEnd: number
): boolean {
  return findingStart <= expEnd && expStart <= findingEnd;
}

export function matchFindings(actual: Finding[], expected: BenchExpectation[]): BenchMatchResult {
  const matchedFindingIds = new Set<string>();
  const matchedExpectationIndexes = new Set<number>();
  const truePositives: BenchMatch[] = [];

  for (let e = 0; e < expected.length; e += 1) {
    const expectation = expected[e];
    for (const finding of actual) {
      if (matchedFindingIds.has(finding.id)) {
        continue;
      }
      if (finding.category !== expectation.category || finding.filePath !== expectation.filePath) {
        continue;
      }
      if (expectation.lineStart !== undefined) {
        const expStart = expectation.lineStart;
        const expEnd = expectation.lineEnd ?? expectation.lineStart;
        if (!rangesOverlap(finding.lineStart, finding.lineEnd, expStart, expEnd)) {
          continue;
        }
      }
      truePositives.push({ expectation, findingId: finding.id });
      matchedFindingIds.add(finding.id);
      matchedExpectationIndexes.add(e);
      break;
    }
  }

  const falsePositives = actual.filter((finding) => !matchedFindingIds.has(finding.id)).map((finding) => finding.id);
  const falseNegatives = expected.filter((_, index) => !matchedExpectationIndexes.has(index));

  return { truePositives, falsePositives, falseNegatives };
}

export function computeMetrics(result: BenchMatchResult): BenchMetrics {
  const tp = result.truePositives.length;
  const fp = result.falsePositives.length;
  const fn = result.falseNegatives.length;

  const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 1 : tp / (tp + fn);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);

  return { tp, fp, fn, precision, recall, f1 };
}
