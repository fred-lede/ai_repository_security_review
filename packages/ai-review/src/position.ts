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