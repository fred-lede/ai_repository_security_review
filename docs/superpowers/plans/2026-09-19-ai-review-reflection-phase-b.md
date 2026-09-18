# Reflection Pass — Phase B Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional adversarial "reflection" pass to `runAiReview`: after batched review + coverage, a second lightweight agent loop tries to **disprove** covered Critical/High findings, producing per-finding verdicts that prune false positives.

**Architecture:** New `reflect.ts` in `packages/ai-review` builds a skeptic prompt over the covered high-risk findings and reuses `runAgentLoop` with a custom `parseResponse`/`finalExample` (same pattern as `deepdive.ts`). `runAiReview` invokes it after the batch loop, subject to a new `AiReviewOptions.reflection` flag (default **on**) and remaining time budget. Results attach additively as `AiReviewResult.reflections`.

**Tech Stack:** TypeScript, Vitest, existing `packages/ai-review` (agent loop, tools, providers).

**Context:**
- Run from repo root: tests `npx vitest run packages/ai-review`, typecheck `npm run typecheck --workspace @repo-auditor/ai-review`.
- `runAgentLoop(config, systemPrompt, initialPrompt, tools, ctx, { maxRounds, maxTokensPerReview, parseResponse, finalExample }, fetchImpl)` — see `deepdive.ts` for the custom-schema pattern (`parseDeepDiveResponse`, `DEEP_DIVE_FINAL_EXAMPLE`).
- `review.test.ts` has top-level `report`/`config` fixtures; copy shapes, don't import across tests.
- Do NOT mutate `findingNotes`; `reflections` is a separate list. Electron rendering is Phase C — do not touch Electron.

---

### Task 1: `reflect.ts` — reflection prompt, parser, and runner

**Files:**
- Create: `packages/ai-review/src/reflect.ts`
- Create: `packages/ai-review/tests/reflect.test.ts`
- Modify: `packages/ai-review/src/types.ts`
- Modify: `packages/ai-review/src/index.ts`

- [ ] **Step 1: Types.** In `types.ts` add:

```ts
export type ReflectionVerdict = "reaffirmed" | "likely-false-positive" | "uncertain";

export interface AiReflection {
  findingId: string;
  verdict: ReflectionVerdict;
  reasoning: string;
}
```

And add `reflections?: AiReflection[];` to `AiReviewResult`, plus `reflection?: boolean;` to `AiReviewOptions`. Export `AiReflection` and `ReflectionVerdict` from index.ts.

- [ ] **Step 2: New module `reflect.ts`.** Shape (mirror deepdive.ts conventions; `closing` parse keys tolerant like `normalizeVerdict` in deepdive):

```ts
import type { AuditReport, Finding } from "@repo-auditor/scanner-core";
import { extractJsonObject, parseToolCall, runAgentLoop, type AgentResponse } from "./agent.js";
import type { FetchLike } from "./providers.js";
import { serializeFindingForPrompt } from "./review.js";
import { redactSecrets } from "./redaction.js";
import { buildTools, type ReviewToolContext } from "./tools.js";
import type { AiProviderConfig, AiReflection, ReflectionVerdict } from "./types.js";

export interface ReflectionRunResult {
  reflections: AiReflection[];
  raw: string;
  truncated: boolean;
}

export interface ReflectionOptions {
  maxRounds?: number;
  maxTokensPerReview?: number;
  scanPath?: string;
}

function normalizeVerdict(value: unknown): ReflectionVerdict { /* reaffirmed | likely-false-positive | uncertain, tolerant key matching like deepdive */ }

export function parseReflectionResponse(text: string): AgentResponse<{ reflections: AiReflection[] }> { /* tool_call passthrough; final: { type:"final", result:{ reflections:[...] } }, tolerating findingId key variants like agent.ts normalizeNote */ }

export const REFLECTION_FINAL_EXAMPLE =
  '{"type":"tool_call","tool":"<name>","args":{...}}  or  {"type":"final","reflections":[{"findingId":"...","verdict":"reaffirmed|likely-false-positive|uncertain","reasoning":"..."}]}';

export function buildReflectionSystemPrompt(config: AiProviderConfig): string; // You are an adversarial re-reviewer; try to DISPROVE each finding; only reaffirm with evidence. Tool guidance per dataSharingMode, same wording pattern as deepdive.

export function buildReflectionPrompt(findings: Finding[], report: AuditReport, config: AiProviderConfig): string; // per-language instruction (same 3-locale map as review.ts), list serialized findings, ask for one verdict per findingId.

export async function runReflection(
  findings: Finding[],
  report: AuditReport,
  config: AiProviderConfig,
  options: ReflectionOptions = {},
  fetchImpl?: FetchLike
): Promise<ReflectionRunResult> // scanPath ctx + tools like deepdive (allowedFiles = finding filePaths in snippets mode); on throw → { reflections: [], raw: "", truncated: true }, like deepdive's catch.
```

Keep `AiReflection.findingId` values filtered down to the input findings' ids (drop hallucinated ids).

- [ ] **Step 3: Tests (TDD).** `reflect.test.ts` cases:
1. `normalizeVerdict`-equivalent: parse `"FALSE_POSITIVE"`, `"fp"`, `"likely-false-positive"` → `likely-false-positive`; `"real"/"confirmed"/"reaffirmed"` → `reaffirmed`; unknown → `uncertain`.
2. `parseReflectionResponse` returns tool_call passthrough and drops hallucinated findingIds (≥1 in, && extra bogus dropped in runner — filtering can live in runReflection; test whichever layer you implement, state where).
3. `runReflection` happy path: fetchImpl returning final with reflections; assert result, and that `runAgentLoop` was driven once (single fetch call when no tool calls returned).
4. `runReflection` returns `{ truncated: true, reflections: [] }` when fetch throws.

Use the standard `fetchImpl` mock pattern from `review.test.ts` (json → choices[0].message.content JSON string).

**Tests for types/exports:** compile-level (typecheck) suffices; no runtime test needed for types themselves.

- [ ] **Step 4:** Run `npx vitest run packages/ai-review/tests/reflect.test.ts` → pass. Then full `npx vitest run packages/ai-review` still green. Typecheck clean.

- [ ] **Step 5: Commit**
```bash
git commit -m "feat(ai-review): add adversarial reflection pass module"
```

---

### Task 2: Wire reflection into `runAiReview`

**Files:**
- Modify: `packages/ai-review/src/review.ts`
- Modify: `packages/ai-review/tests/review.test.ts`

- [ ] **Step 1:** After coverage computation and position correction, run reflection when:
- `options.reflection !== false` (default on), AND
- at least one finding is `riskLevel` Critical or High AND in `coverage.covered` (only reflect on actually-covered ones; reflect on all covered Critical/High from `report.findings`), AND
- `Date.now() < deadline` (time left), AND
- batches loop didn't hit abort controller.

Attach `reflections` only when non-empty (omit key / leave undefined otherwise). Call `runReflection(targets, report, config, { scanPath: scanPath ?? "" }, fetchImpl)`; cap targets at 20 sorted Critical-first, sorted by risk order.

- [ ] **Step 2: Tests in review.test.ts:**
1. config fixture with a Critical finding: default run includes `reflections`; verdict from mock appears.
2. `reflection: false` → no extra fetch call count growth / `result.reflections` undefined.
3. Reflection fetch failing → result still returned, `reflections` undefined, no crash.

Mock shape: first fetch = batch final; second fetch = reflection final. Use a fetchImpl that switches on call index.

- [ ] **Step 3:** `npx vitest run packages/ai-review` all pass; typecheck clean.

- [ ] **Step 4: Commit**
```bash
git commit -m "feat(ai-review): run adversarial reflection on covered high-risk findings"
```

---

### Task 3: Verification

- [ ] `npm run build --workspace @repo-auditor/ai-review`
- [ ] `npx vitest run apps/electron` — 21/21 pass (result contract untouched; additive field only).
- [ ] `npm run typecheck --workspaces --if-present` clean.
