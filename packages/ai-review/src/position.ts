import fs from "node:fs/promises";
import path from "node:path";
import type { Finding } from "@repo-auditor/scanner-core";

export interface SnappedRange {
  lineStart: number;
  lineEnd: number;
}

const clamp = (n: number, min: number, max: number): number => Math.min(Math.max(n, min), max);
const toInt = (n: number): number => (Number.isFinite(n) ? Math.floor(n) : 1);

export function snapFindingPosition(
  lines: string[],
  lineStart: number,
  lineEnd: number,
  codeSnippet?: string
): SnappedRange {
  let total = lines.length;
  while (total > 0 && lines[total - 1] === "") {
    total -= 1;
  }
  if (total === 0) {
    return { lineStart: 1, lineEnd: 1 };
  }

  const start = clamp(toInt(lineStart), 1, total);
  const end = clamp(Math.max(toInt(lineEnd), start), start, total);

  const firstSnippetLine = codeSnippet?.split(/\r?\n/)[0]?.trim();
  if (!firstSnippetLine) {
    return { lineStart: start, lineEnd: end };
  }

  const windowStart = Math.max(1, start - 30);
  const windowEnd = Math.min(total, start + 30);
  for (let i = windowStart; i <= windowEnd; i += 1) {
    if (lines[i - 1]?.trim() === firstSnippetLine) {
      const delta = i - start;
      return {
        lineStart: clamp(start + delta, 1, total),
        lineEnd: clamp(end + delta, 1, total)
      };
    }
  }

  return { lineStart: start, lineEnd: end };
}

export async function readLinesWithin(root: string, relPath: string): Promise<string[]> {
  const rootAbs = path.resolve(root);
  const resolved = path.resolve(rootAbs, relPath);
  if (resolved !== rootAbs && !resolved.startsWith(rootAbs + path.sep)) {
    throw new Error(`path escapes scan directory: ${relPath}`);
  }
  const content = await fs.readFile(resolved, "utf8");
  const lines = content.split(/\r?\n/);
  while (lines.length > 0 && lines[lines.length - 1] === "") {
    lines.pop();
  }
  return lines;
}

export async function correctFindingPositions(
  findings: Finding[],
  scanPath: string
): Promise<Finding[]> {
  if (!scanPath || findings.length === 0) {
    return findings;
  }

  const cache = new Map<string, string[] | undefined>();
  const out: Finding[] = [];

  for (const finding of findings) {
    if (!finding.filePath) {
      out.push(finding);
      continue;
    }
    if (!cache.has(finding.filePath)) {
      try {
        cache.set(finding.filePath, await readLinesWithin(scanPath, finding.filePath));
      } catch {
        cache.set(finding.filePath, undefined);
      }
    }
    const lines = cache.get(finding.filePath);
    if (!lines) {
      out.push(finding);
      continue;
    }
    const snapped = snapFindingPosition(lines, finding.lineStart, finding.lineEnd, finding.codeSnippet);
    out.push({
      ...finding,
      lineStart: snapped.lineStart,
      lineEnd: snapped.lineEnd
    });
  }

  return out;
}
