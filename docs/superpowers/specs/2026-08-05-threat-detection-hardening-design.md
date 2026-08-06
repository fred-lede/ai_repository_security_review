# Threat Detection Hardening: Phishing, Network Attack, Data Exfiltration — Design Spec

## Goal

Close the coverage gap for three threat families the current scanner under-detects: **phishing**, **network attacks**, and **data exfiltration**. Current detection strength is RCE / command injection / supply chain; these three families are nearly absent in the deterministic layer, and the AI review layer is forbidden from creating new findings ("Do not create new findings. Explain only the evidence provided.").

Two tracks:

1. **Track 1 — Deterministic threat-pattern module**: a new standalone module (`threatPatterns.ts`) with per-family signals (reverse shell, bind shell, SSRF sink, port scan, credential harvesting, keylogger, bulk email, webhook/encoded/non-HTTP/file-upload exfiltration sinks) plus 6 new rules, including **cross-file exfiltration correlation** (sensitive source anywhere + exfiltration sink anywhere → `exfiltration-candidate`).
2. **Track 2 — AI layer relax + new-finding merge**: allow the AI agent to create new findings limited to the three threat families, marked `source: "ai"`, capped at `Medium` risk / `Low` confidence, never auto-Blocking; merge them into `report.findings` and recompute risk. Plus **LLM context-window budget management and overall wait-time control**.

## Background

### Current deterministic layer

- `inventory.ts` — `LANGUAGE_PATTERNS` (7 languages: python/javascript/go/java/shell/dockerfile/yaml) cover only RCE/command-injection/supply-chain signals. Collects `dangerousCalls`, `commandExecutions`, `networkEndpoints`, `environmentVariables`, `filesystemReads`, `persistenceIndicators`, `packageScripts`, `dependencySources`, `githubWorkflowFiles`, `electronIpcFiles`.
- `defaultRules.ts` — 21 `BuiltinRule`s + the `networkRule` handler. `networkRule` marks `exfiltration-candidate` only when env var / file read / command execution coexists **in the same file** as an endpoint.
- `dataFlow.ts` — `buildDataFlowGraph` already correlates sources (env/fs) → APIs (network/command/local) → external destinations across files, but only for the display layer (Mermaid). It has no effect on findings.
- `risk.ts` — `assessRisk` blocks on `Critical`, or `High + High confidence` in blocking categories (which includes `data-exfiltration`) or `exfiltration-candidate` tag.
- `FindingCategory` already reserves `data-exfiltration`, `credential-leakage`, `hidden-telemetry`, `tracking`. It lacks `phishing` and `network-attack`.

### Current AI review layer

- `review.ts` — `buildAiReviewPrompt` explicitly instructs: "Do not create new findings. Explain only the evidence provided." `runAiReview` batches findings (10/batch) and runs an agent loop per batch with tools (`file_read`, `file_find`, `code_search`) gated by `dataSharingMode`.
- `agent.ts` — `runAgentLoop` with `maxRounds` (default 6) and `maxTokensPerReview` (default 200k); `estimateTokens` = `ceil(length/4)`; decrements budget per round; stops when budget exhausted. `AgentFinalResult` = `{ summary, notes[] }`.
- `providers.ts` — `requestProviderCompletion` with per-request `timeoutMs` (UI default 120s) and `retryLimit` (UI default 1).
- `AiReviewResult` = `{ providerType, model, generatedAt, summary, findingNotes[] }`. Findings are never modified by AI.

### Reported gap

The three threat families have essentially no dedicated detection:

- **Data exfiltration**: only same-file heuristic; non-HTTP channels (nc/socat/scp/rsync/FTP/S3), email (smtplib/nodemailer), webhooks (Discord/Telegram/Slack), encoded chains (base64→endpoint, btoa/atob), file upload (`curl -d @file`) all undetected. Cross-file source→sink splits are missed.
- **Phishing**: nothing. No credential harvesting, keyloggers, bulk email, telegram-bot forwarding, cookie/extension theft.
- **Network attacks**: only injection/execution patterns. Reverse/bind shells (`/dev/tcp`, `nc -e`, `socat TCP-LISTEN`), SSRF sinks (`requests.get(var)`, `urlopen`, `fetch(var)`), port scanning (`connect_ex`, nmap/masscan) all undetected.

## Track 1 Design — Deterministic Threat Patterns

### 1a. New module `packages/scanner-core/src/threatPatterns.ts`

New `ThreatFamily = "phishing" | "network-attack" | "data-exfiltration"` and a `ThreatSignal` record:

```ts
export interface ThreatSignal {
  family: ThreatFamily;
  pattern: string;
  filePath: string;
  line: number;
  snippet: string;
  evidenceTags: string[];
}
```

Per-family patterns (line-based regex, path-scoped where useful), collected into a new `inventory.threatSignals: ThreatSignal[]` field by `buildInventory`:

| family | signal id | regex example | risk |
|---|---|---|---|
| network-attack | reverse-shell-dev-tcp | `/(?:\/dev\/tcp\/|bash\s+-i\s+>&)/` | Critical |
| network-attack | reverse-shell-nc | `/\bnc(?:at)?\s+-[^\n]*\s+-e\s+\/(?:bin|usr)\/(?:ba)?sh/` | Critical |
| network-attack | bind-shell | `/\b(?:nc(?:at)?|ncat)\s+-l[^\n]*(?:\s+-p\s+\d+)?/` + `socat TCP-LISTEN` | Critical |
| network-attack | ssrf-sink | `/(?:requests\.(?:get|post|request)\(\s*[^"']|urllib(?:\.request)?\.urlopen\(\s*[^"']|fetch\(\s*[a-zA-Z_$]|axios\.(?:get|post|request)\(\s*[^"'])/` | High |
| network-attack | port-scan | `/\bconnect_ex\s*\(|nmap|masscan/` | Medium |
| phishing | credential-harvest | password input + outbound (two-line window) / `getElementById(?:By)*\(['"]password|localStorage|chrome\.(?:storage|cookies)/` | Critical |
| phishing | keylogger | `/\b(?:addEventListener\(\s*['"]keydown|pynput|hook_all)/` | High |
| phishing | bulk-email | `/\bsmtplib\.SMTP\s*\(|nodemailer\s+createTransport|sendmail/` | High |
| data-exfiltration | webhook-sink | `/(?:discord\.com\/api\/webhooks|api\.telegram\.org|hooks\.slack\.com|webhook\.site|requestbin)/` | Critical |
| data-exfiltration | encoded-sink | `/\bbase64\s+(?:-d|--decode)[^\n]*\|\s*(?:curl|nc|wget)|\b(?:btoa|atob)\s*\(|Buffer\.from\([^,]+,\s*['"]base64['"]\)/` | High |
| data-exfiltration | non-http-sink | `/\b(?:nc|ncat|socat|scp|rsync)\b[^\n]*\s+(?:[0-9]{1,3}\.){3}[0-9]{1,3}|:\d{4,5}\b|\b(?:ftp|sftp)\s+[^\s]+/` | High |
| data-exfiltration | file-upload-sink | `/\bcurl\s+[^\n]*(?:-d\s+@|\-F\s+)/` | High |

Collections reuse the existing `collectLineMatches`-style per-line scan and the existing `unique` de-duplication. Signals with matching `filePath`/`line`/`pattern` are deduped.

### 1b. New built-in rules (6)

In `defaultRules.ts` (or a `threatRules.ts` imported into the rule pipeline), mapping `threatSignals` to findings:

| rule id | category | default risk | notes |
|---|---|---|---|
| `reverse-shell` | network-attack | Critical | matches reverse-shell-* and bind-shell |
| `ssrf-sink` | network-attack | High | |
| `port-scan` | network-attack | Medium | |
| `credential-harvest` | phishing | Critical | |
| `keylogger` | phishing | High | |
| `exfiltration-sink` | data-exfiltration | High/Critical | uses cross-file correlation (see 1c) |

### 1c. Cross-file exfiltration correlation

Extend `networkRule` logic into a shared helper `assessExfiltrationCandidate(inventory)`:

- **Same-file** (existing behavior): sensitive source (env var, fs read, command exec) + endpoint/sink in same file → `exfiltration-candidate`.
- **Cross-file** (new): inventory has at least one sensitive source (any file) **and** at least one exfiltration sink (`webhook-sink`/`encoded-sink`/`non-http-sink`/`file-upload-sink`, any file) → every exfiltration sink finding gets the `exfiltration-candidate` tag and `data-exfiltration` category with High risk.

The cross-file check intentionally requires a concrete sink signal (not any endpoint) to control false positives. `risk.ts` already treats `exfiltration-candidate` as blocking at High+High-confidence, so cross-file sink findings participate in Block.

### 1d. Types, risk, i18n

- `types.ts` — add `"phishing" | "network-attack"` to `FindingCategory`; add `threatSignals` to `ProjectInventory`.
- `risk.ts` — add `"phishing"` and `"network-attack"` to `blockingCategories` (deterministic findings only; see Track 2 for the `source === "ai"` exclusion).
- `i18n.ts` — category labels for `phishing` and `network-attack` in all three languages (en / zh-TW / zh-CN); explanation/recommendedFix strings for the 6 new rules in the same three languages.

## Track 2 Design — AI New-Finding Merge + Budget/Wait Control

### 2a. AI new findings

- `AgentFinalResult` gains `newFindings?: AiNewFinding[]` where

  ```ts
  export interface AiNewFinding {
    category: "phishing" | "network-attack" | "data-exfiltration";
    filePath: string;
    lineStart: number;
    lineEnd: number;
    codeSnippet: string;
    explanation: string;
    recommendedFix: string;
  }
  ```

- `parseAgentResponse` parses `newFindings` from the `final` object (validated by `normalizeAiFindings`).
- `buildAiReviewPrompt` / `buildBatchPrompt` prompt text changes:
  - Remove "Do not create new findings."
  - Instruct: you MAY add new findings for phishing, network attack, or data exfiltration only; every new finding must be verified against real code via `file_read`/`code_search` before being reported; other categories require deterministic evidence and must not be invented.
- New `normalizeAiFindings(newFindings, ctx)`:
  - category whitelist: only the three families (others dropped)
  - riskLevel capped at `Medium`, confidence forced to `Low`
  - must have non-empty `filePath` and `codeSnippet` and plausible `lineStart`/`lineEnd`; else dropped
  - `source: "ai"` on the resulting `Finding`
  - dropped findings are not errors; the merge still succeeds.
- `AiReviewResult` gains `newFindings: Finding[]` (already normalized).

### 2b. Merge into report + risk recompute

- New exported `mergeAiFindingsIntoReport(report: AuditReport, result: AiReviewResult): AuditReport` in `ai-review`:
  - appends `result.newFindings` to `report.findings`
  - recomputes `report.risk` via `assessRisk`
  - recomputes `report.attackSurface` (category counts include new findings)
  - returns the merged report.
- `apps/electron/src/main.ts` `ai-review:run` handler returns `{ ...result, mergedReport }`; the renderer re-renders findings/risk from `mergedReport`.
- `risk.ts` `assessRisk` excludes `source === "ai"` findings from the blocking predicate (defense in depth on top of the Medium cap).

### 2c. LLM context-window budget management

- `AiProviderConfig` gains `contextWindow?: number`. Default by provider: cloud/custom → **131072** (128k), ollama → **32768** (32k). UI field allows override.
- Effective agent budget per review = `min(maxTokensPerReview, contextWindow * 0.7)` — reserve ~30% of the window for generation output to avoid truncation. `maxTokensPerReview` default stays 200k but is capped by `contextWindow * 0.7`.
- **History pruning**: in `runAgentLoop`, if the built prompt exceeds the effective budget, drop the **oldest `<tool_result>`** entry (keep system prompt, initial prompt, latest round). Loop continues so the agent can still reach `final`.
- The `newFindings` batch prompt participates in the same `estimateTokens` accounting as all other history entries.

### 2d. Overall wait-time control

- `AiReviewOptions` gains `maxTotalMs?: number` (default **600000** / 10 min) and `onBatchProgress?: (done: number, total: number) => void`.
- `runAiReview` shares one `AbortController` across the sequential batch loop; when the deadline elapses, remaining batches are aborted and the result is returned with a `truncated: true` flag on `AiReviewResult` (partial results, not a failure).
- Per-request `timeoutMs` (120s) and `retryLimit` (1) unchanged.
- Renderer: AI wait copy shows "batch x/y done"; `timeoutMs` remains user-adjustable.

## Data Flow

```
scanTarget(input)
  → buildInventory(scanPath)            [Track 1: + threatSignals collection]
  → runRules(inventory)                 [Track 1: + 6 threat rules, cross-file exfil]
  → assessRisk → report (+ coverage)
  → renderOutputs
runAiReview(report, config, { scanPath, maxTotalMs, onBatchProgress })
  [Track 2: per-batch agent loop, context-window budget, history pruning,
   newFindings verified via tools → normalizeAiFindings]
  → AiReviewResult { summary, findingNotes[], newFindings[], truncated? }
mergeAiFindingsIntoReport(report, result)  [Track 2: append + assessRisk recompute]
  → mergedReport → Electron renderer / exporters
```

## Files Changed

Track 1:
- `packages/scanner-core/src/threatPatterns.ts` — new module (ThreatSignal, families, patterns)
- `packages/scanner-core/src/inventory.ts` — `threatSignals` field + collector
- `packages/scanner-core/src/defaultRules.ts` — 6 new rules + exfiltration correlation helper
- `packages/scanner-core/src/types.ts` — `phishing`/`network-attack` categories, `ThreatSignal`, `ProjectInventory.threatSignals`
- `packages/scanner-core/src/risk.ts` — blocking categories + `source === "ai"` exclusion
- `packages/scanner-core/src/i18n.ts` — category labels + rule strings (3 languages)
- `packages/scanner-core/src/index.ts` — export new module/types
- `README.md` — detection-rules table, finding-categories count/table (15→17), AI review section (new-finding capability, context window, batch progress)
- tests: `tests/threatPatterns.test.ts` (new), `tests/rules.test.ts`, `tests/risk.test.ts`

Track 2:
- `packages/ai-review/src/agent.ts` — `newFindings` in `AgentFinalResult`, parsing, history pruning
- `packages/ai-review/src/review.ts` — prompt relaxation, batch loop deadline + progress, `normalizeAiFindings`, `mergeAiFindingsIntoReport`
- `packages/ai-review/src/types.ts` — `contextWindow`, `maxTotalMs`, `onBatchProgress`, `AiNewFinding`, `newFindings`, `truncated`
- `packages/ai-review/src/index.ts` — export new APIs
- `apps/electron/src/main.ts` — `ai-review:run` returns `mergedReport`; renderer re-render
- `apps/electron/src/renderer/index.html` — batch progress copy
- tests: `packages/ai-review/tests/agent.test.ts`, `tests/review.test.ts`, `apps/electron/tests/ipc.test.ts`

## Out of Scope

- Real taint analysis / data-flow tracking in the deterministic layer (cross-file correlation stays signal-based, using concrete sink patterns to bound false positives).
- Async / concurrent batch execution (sequenced to keep deadline and progress deterministic in v1).
- New output formats; existing reporters render new findings automatically via `report.findings`.
- Detecting phishing via reputation/lookalike URLs (requires network lookups; out of the deterministic offline model).
