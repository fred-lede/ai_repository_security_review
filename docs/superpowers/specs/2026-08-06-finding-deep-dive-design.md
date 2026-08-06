# Per-Finding AI Deep-Dive — Design Spec

## Goal

Add an on-demand **single-finding AI deep-dive** to the Electron app: each finding panel in the middle column gets an "AI 深入分析" button that runs a focused, tool-enabled agent loop on that one finding and renders a rich result inline — verdict, detailed analysis, step-by-step fix suggestions, and a suggested corrected code snippet.

The feature is a **supplement** to the existing batch AI review (which stays as-is for fast triage), is **display-only** (results never write back into the report, the risk decision, or exports), and does **not** auto-apply patches.

## Background

### Current AI review layer

- `runAiReview` (packages/ai-review/src/review.ts) groups findings by category into batches (max 10/batch), runs one `runAgentLoop` per batch, and merges per-finding `AgentNote { findingId, explanation, falsePositiveNote?, saferPattern? }` into `findingNotes`. Because many findings share one prompt, per-finding output is one-liner depth.
- `runAgentLoop` (packages/ai-review/src/agent.ts) supports tool calls (`file_read`, `file_find`, `code_search` gated by `dataSharingMode`) and a multi-round loop with a token budget. Its JSON schema is hardcoded to the batch final object `{"type":"final","summary","notes","newFindings"}`.
- `requestProviderCompletion` (providers.ts) enforces per-request `timeoutMs`/`retryLimit`. The batch loop wraps `runAgentLoop` in try/catch so an AbortError degrades to `truncated: true` instead of failing the whole review.
- Electron IPC: `ai-review:run` handler in apps/electron/src/main.ts; channel allowlist in ipc.ts; preload in preload.ts. Renderer is a single inline script in apps/electron/src/renderer/index.html.

### Motivation

A focused single-finding prompt lets the model read the exact code (and use tools to verify surrounding context) and return a much deeper analysis than a batched note, including an explicit verdict and a corrected-code snippet. This matches the standard SAST workflow: scan → triage → click into a finding for detail.

## Design

### 1. Backend — new module `packages/ai-review/src/deepdive.ts`

**Types**

```ts
export type DeepDiveVerdict = "real" | "false-positive" | "uncertain";

export interface DeepDiveResult {
  verdict: DeepDiveVerdict;
  analysis: string;
  fixSteps: string[];
  correctedCode: string;
}

export interface DeepDiveRunResult {
  result?: DeepDiveResult;
  raw: string;
  truncated: boolean;
}

export interface DeepDiveOptions {
  maxRounds?: number;
  maxTokensPerReview?: number;
  scanPath?: string;
}
```

**`parseDeepDiveResponse(text: string)`**

Tolerant parser modeled on `parseAgentResponse`/`normalizeNote` (reuse `extractJsonObject`):
- `type: "tool_call"` → passthrough so the loop can continue tool rounds.
- `type: "final"` → build `DeepDiveResult` with alias normalization:
  - verdict: `real`/`vulnerable`/`true` → `real`; `false-positive`/`false`/`benign`/`not-an-issue` → `false-positive`; anything else → `uncertain`.
  - analysis: keys `analysis`/`detail`/`explanation` (fallback `""`).
  - fixSteps: string[] from `fixSteps`/`steps`/`recommendations`, or split a string on newlines.
  - correctedCode: keys `correctedCode`/`code`/`patch` (fallback `""`).
- Invalid → `undefined`.

**`buildDeepDivePrompt(finding, report, config)`**

Single-finding prompt:
- System prompt: analyze exactly this one finding; you may use tools (`file_read`/`file_find`/`code_search`) to verify evidence in the real code before concluding; respond with a single JSON `{"type":"final","verdict":"real|false-positive|uncertain","analysis":"...","fixSteps":[...],"correctedCode":"..."}`. Language instruction per `config.language` (mirror `buildAiReviewPrompt`'s `langInstruction`).
- Initial prompt: the finding serialized with `serializeFindingForPrompt` (exported from review.ts), plus a note that the verdict must reflect verified evidence.
- Apply `redactSecrets` when `config.redactionEnabled` (consistent with the batch path).

**`runDeepDive(finding, report, config, options?, fetchImpl?)`**

- Build tool context exactly like `runAiReview`: `scanPath = options.scanPath ?? report.target.localPath ?? ""`; `mode` and `allowedFiles` from `dataSharingMode`; `tools = buildTools(dataSharingMode, ctx)`.
- Call `runAgentLoop` with the deep-dive system prompt, initial prompt, tools, ctx, and options `{ maxRounds: options.maxRounds ?? 6, maxTokensPerReview: options.maxTokensPerReview ?? 30_000 }`.
- Wrap in try/catch → on abort/error return `{ result: undefined, raw, truncated: true }` (mirror the batch loop).
- If the loop returns no `result` (parse failure or `maxRounds` exhausted), return `{ result: undefined, raw, truncated: false }` — the renderer shows the raw fallback. `truncated: true` is reserved for aborts only (same contract as the batch loop).

### 2. Shared-loop generalization in `packages/ai-review/src/agent.ts`

Backward-compatible change so the deep-dive can reuse the battle-tested loop:

- `buildAgentPrompt(systemPrompt, tools, history, finalExample?)` — the trailing "RESPOND WITH A SINGLE JSON OBJECT" example line becomes parameterizable, defaulting to the current batch example.
- `runAgentLoop(..., options, fetchImpl?)` gains optional `parseResponse?: (text: string) => AgentResponse` and `finalExample?: string` (threaded into `buildPromptWithinBudget`/`buildAgentPrompt`). Default `parseResponse` = `parseAgentResponse`. Batch behavior unchanged; existing agent tests prove it.

### 3. IPC + preload

- `apps/electron/src/main.ts` new handler `finding:review`:
  - Payload `{ finding: Finding; report: AuditReport; provider: AiProviderPayload; language?: Language }`.
  - `assertAllowed("finding:review")`; validate `finding.id` and `finding.filePath` present (else return `{ error }`).
  - Provider config built like `ai-review:run`: `{ ...provider, language: provider.language ?? "zh-TW", redactionEnabled: true, timeoutMs: 120000, retryLimit: 1 }`.
  - Return `{ result?, raw, truncated, error? }` — never throws on abort; errors returned in the payload.
- `apps/electron/src/ipc.ts`: add `"finding:review"` to the channel allowlist.
- `apps/electron/src/preload.ts`: expose `findingReview(payload)` → `invoke("finding:review", payload)`.

### 4. Renderer — `apps/electron/src/renderer/index.html`

- In `renderResult`'s per-finding `detail` (next to the "顯示上下文" button): add button `aiDeepDive` ("AI 深入分析").
- Click handler (per-finding, independent DOM state):
  1. Disable the button, set its text to `aiDeepDiveReviewing` ("深入分析中…").
  2. `const res = await window.repoAuditor.findingReview({ finding, report: state.result.report, provider: { ...form fields }, language: currentLang() })`.
  3. Render inline below the button:
     - Verdict badge: `real` → `aiVerdictReal` (red), `false-positive` → `aiVerdictFalsePositive` (green), `uncertain` → `aiVerdictUncertain` (gray).
     - `analysis` paragraph(s).
     - `fixSteps` ordered list.
     - `correctedCode` in a `<pre class="finding-patch">`.
  4. `res.truncated && !res.result` → show `res.raw` in a `<pre>` plus a `aiDeepDiveTruncated` note.
  5. `res.error` or thrown IPC error → inline `aiDeepDiveFailed` message in that finding only.
  6. Re-enable the button in a `finally`.
- No changes to `state.result`, the report, the decision, or the export payload.
- i18n keys (en / zh-TW / zh-CN): `aiDeepDive`, `aiDeepDiveReviewing`, `aiDeepDiveFailed`, `aiDeepDiveTruncated`, `aiVerdictReal`, `aiVerdictFalsePositive`, `aiVerdictUncertain`, `aiAnalysis`, `aiFixSteps`, `aiCorrectedCode`.

### 5. Error handling summary

- Provider abort / timeout → `{ truncated: true, raw }`, renderer shows raw + truncation note (same graceful-degradation contract as the batch review).
- Parse failure / max rounds exhausted → `{ result: undefined, raw }`, renderer shows raw.
- Invalid finding payload → `{ error }`, renderer shows inline failure.
- `correctedCode` is never executed — display-only, rendered as text.

## Out of scope

- Writing deep-dive results back into the report / `findingNotes` / merged outputs.
- Affecting the overall risk decision.
- Including deep-dive results in `report:export`.
- Auto-applying or executing `correctedCode`.
- Replacing the batch review.

## Testing

- `packages/ai-review/tests/deepdive.test.ts`:
  - `parseDeepDiveResponse` — full valid object; alias keys (verdict variants, `analysis`/`detail`, string vs array `fixSteps`, `correctedCode`/`code`/`patch`); tool_call passthrough; garbage → undefined.
  - `runDeepDive` — happy path returns parsed result (mocked fetch final); abort → `truncated: true`; invalid model response → `result: undefined` with raw preserved.
- `packages/ai-review/tests/agent.test.ts` — unchanged, proves the shared-loop default path still works.
- `apps/electron/tests/ipc.test.ts` — `finding:review`: missing finding → error; happy path returns `DeepDiveRunResult`; provider failure → error payload (no throw).
- Full `npm test` (expect 144 + new), per-workspace `typecheck`, build electron + rebuild ai-review dist.

## Notes

- `dev:electron` rebuilds `scanner-core` + `ai-review` before launching (stale-dist lesson from `12402f3`), so the new `deepdive.js` is picked up automatically.
