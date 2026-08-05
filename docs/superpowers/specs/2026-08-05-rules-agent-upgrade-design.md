# Language-Aware Rules + AI Review Agent — Design Spec

## Goal

Reference the hybrid architecture of [alibaba/open-code-review](https://github.com/alibaba/open-code-review) (deterministic pipeline + LLM agent) to upgrade this tool in two tracks:

1. **Track 1 — Language-aware deterministic rules**: make inventory collection and rule matching language/path-aware, adding security rules for Python, JavaScript/TS, Go, Java, Shell, Dockerfile, and GitHub Actions YAML. This reduces both missed detections and false-positive noise (motivated by the observed gap: GitHub scan found 116 findings vs npm package 3 findings on the same repo).
2. **Track 2 — Multi-round AI review agent**: upgrade the AI review layer from a passive one-shot JSON explanation into a tool-using agent loop (`file_read`, `file_find`, `code_search`) with token budget, max rounds, and privacy-scaled tool permissions, reviewing findings in per-category batches.

## Background

### Current scanner-core architecture

- `inventory.ts` collects **generic regex** signals across all files: `commandExecutions` (`exec|spawn|execFile|curl|bash`), `filesystemReads`, `networkEndpoints` (any `http(s)://`), `environmentVariables` (`process.env.X`), `packageScripts`/`dependencySources` (package.json only), `githubWorkflowFiles`, `electronIpcFiles`, `persistenceIndicators`.
- `ruleTypes.ts` defines declarative `RuleDefinition` with `conditions` over inventory fields; `defaultRules.ts` defines function-based `BuiltinRule[]` (postinstall-script, unpinned-dependency, command-execution) plus the `networkRule` handler.
- Rules have **no path/language filtering** — the same rule matches any item from any file.
- `fileWalker.ts` only scans `{js,jsx,ts,tsx,mjs,cjs,json,yml,yaml,sh,bash,zsh,Dockerfile}` + `.github/workflows/*` — **`.py`/`.go`/`.java` files are never walked**.
- Language-specific dangerous calls (Python `subprocess`, Java `Runtime.exec`, Go `exec.Command`, Shell `curl|sh`, Dockerfile `ADD http://`, Actions `pull_request_target`) are **not detected**.

### Current ai-review architecture

- `review.ts` serializes the whole report (all findings) into a JSON prompt and sends it in **one request** to the LLM (`requestProviderCompletion`).
- No file access, no search, no tool use. The model can only reason from the snippets already in the findings.
- `AiProviderConfig` has a `dataSharingMode` ("metadata-only" | "finding-snippets" | "full-files") and `redactionEnabled`.
- `AiReviewResult` = `{ providerType, model, generatedAt, summary, findingNotes[] }`.

### Reference: alibaba/open-code-review

- Deterministic pipeline: path-based rule dispatch (`path_rule_map`: `**/*.py` → python.md, `**/package.json` → package_json.md, etc.), precise file selection, file bundling, comment positioning.
- Agent: LLM with scenario-tuned toolset (`file_read`, `file_find`, `code_search`, `file_read_diff`), token budget, concurrency.
- Session persistence/resume, coverage tracking, web viewer.

## Track 1 Design — Language-Aware Rules

### 1a. Language-aware inventory collection

**Prerequisite: extend `fileWalker.ts`** to include the languages in scope:

```
**/*.{js,jsx,ts,tsx,mjs,cjs,json,yml,yaml,sh,bash,zsh,Dockerfile,py,go,java}
```

(`ignore` list unchanged: `node_modules/**`, `dist/**`, `.git/**`, `coverage/**`.)

New types in `inventory.ts`:

```ts
export type LanguageId = "python" | "javascript" | "go" | "java" | "shell" | "dockerfile" | "yaml";

export interface DangerousCall {
  filePath: string;
  line: number;
  snippet: string;
  language: LanguageId;
  pattern: string;          // id of the matched pattern, e.g. "python.subprocess"
  evidenceTags: string[];
}

// ProjectInventory gains:
dangerousCalls: DangerousCall[];
```

A **language pattern table** maps language → file matching rules → list of regex patterns:

```ts
const LANGUAGE_PATTERNS: Record<LanguageId, { match: (file: string) => boolean; patterns: LanguagePattern[] }>
interface LanguagePattern {
  id: string;               // "python.subprocess"
  regex: RegExp;            // /subprocess\.(?:run|call|Popen)\s*\(/
  tags: string[];           // ["rce-candidate", "python"]
}
```

Language→file matching:

| Language | File match |
|---|---|
| python | `**/*.py` |
| javascript | `**/*.{js,jsx,ts,tsx,mjs,cjs}` |
| go | `**/*.go` |
| java | `**/*.java` |
| shell | `**/*.sh`, `**/*.bash`, files starting with `#!...sh` |
| dockerfile | `**/Dockerfile*`, `**/*.dockerfile` |
| yaml | `**/*.{yaml,yml}` (plus `.github/workflows/**`) |

Initial pattern set per language (each maps to evidence tags):

- **python**: `subprocess.{run,call,Popen,check_output}`, `os.system`, `os.popen`, `eval(`, `exec(` (bare), `pickle.loads` from network (optional)
- **javascript**: `child_process.{exec,spawn,fork}`, `eval(`, `new Function`, `require('child_process')` / `require("child_process")`
- **go**: `os/exec` import, `exec.Command(`, `syscall.Exec(`, `os.StartProcess`
- **java**: `Runtime.getRuntime().exec`, `new ProcessBuilder(`, `ScriptEngine.eval`, `InitialContext.lookup` (JNDI), `javax.script`
- **shell**: `curl ... | sh`, `wget ... | sh`, `eval `, `base64 -d ... | sh`, `$(wget|curl|nc) ...`
- **dockerfile**: `ADD http://`, `ADD https://`, `RUN curl ... | sh`, `RUN wget ... | sh`, `ENV` with hardcoded credential patterns (`API_KEY=`, `TOKEN=`, `PASSWORD=`)
- **yaml**: `pull_request_target`, external `uses: <owner>/<repo>@<ref>` (owner not in allowlist), `runs-on: self-hosted`, hardcoded secret values

Existing generic collectors (`commandExecutions`, `filesystemReads`, etc.) remain unchanged for backward compatibility. `dangerousCalls` is additive.

### 1b. Path filtering in rules

`ruleTypes.ts` `RuleDefinition` gains an optional field:

```ts
pathPattern?: string;   // glob, e.g. "**/*.py", "**/Dockerfile*"
```

`compileRule` filters items by `pathPattern` (using `fast-glob`'s matching semantics) before evaluating conditions. `BuiltinRule` gains the same optional `pathPattern`. Existing rules without `pathPattern` behave exactly as before.

### 1c. New built-in rules

New `BuiltinRule`s consume `inventory.dangerousCalls`, filtered by `pathPattern` + `pattern` id. Minimum set (each with category, riskLevel, explanation, recommendedFix, tags, i18n):

| Rule | Pattern(s) | Category | Risk |
|---|---|---|---|
| `python-subprocess-exec` | python.subprocess | command-injection | High |
| `python-eval` | python.eval | remote-code-execution | High |
| `js-child-process` | javascript.child_process | command-injection | High |
| `js-eval` | javascript.eval | remote-code-execution | High |
| `go-exec-command` | go.exec | command-injection | High |
| `java-runtime-exec` | java.runtime_exec, java.process_builder | command-injection | Critical |
| `java-jndi` | java.jndi | remote-code-execution | Critical |
| `shell-pipe-to-sh` | shell.curl_sh, shell.wget_sh | supply-chain | Critical |
| `shell-eval` | shell.eval | remote-code-execution | High |
| `shell-base64-obfuscation` | shell.base64_sh | remote-code-execution | High |
| `dockerfile-add-remote` | dockerfile.add_http | supply-chain | High |
| `dockerfile-run-pipe` | dockerfile.curl_sh | supply-chain | Critical |
| `actions-pr-target` | yaml.pull_request_target | supply-chain | High |
| `actions-external-action` | yaml.external_action | supply-chain | Medium |

For `javascript`/`yaml` rules, `pathPattern` excludes lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` — matched in `pattern.pathPattern`); `node_modules`/`dist` are already excluded by `fileWalker`.

### 1d. Coverage report

`AuditReport` gains a `coverage` field:

```ts
export interface ScanCoverage {
  totalFiles: number;
  filesWithPatterns: number;
  byLanguage: Record<LanguageId, { files: number; detections: number }>;
}
```

Populated in `scan.ts` after `buildInventory`. Rendered in markdown/html reporters as a small table (not in JSON decision record).

## Track 2 Design — Multi-Round AI Review Agent

### 2a. Tools (`tools.ts` in ai-review)

Three tools, all constrained to `scanPath` with **path traversal protection** (resolve path, verify prefix against `scanPath`, reject escapes — mirroring `assertSafeArchiveEntry`):

| Tool | Args | Behavior | gating |
|---|---|---|---|
| `file_read` | `path`, `lineStart?`, `lineEnd?` | returns file content (default full, cap ~2000 lines / 60KB) | snippets: only files referenced in findings; full-files: any file |
| `file_find` | `pattern` | glob for filenames under scanPath | full-files only |
| `code_search` | `query` | regex across file contents (respect `fileWalker`'s scannable list), cap results | full-files only |

`metadata-only` mode: tool list is **empty** — agent reasons from metadata only (equivalent to today's behavior).

Tool results are truncated and merged into the conversation; tool execution failures return a structured error string to the model (never throw).

### 2b. Agent loop (`agent.ts`)

JSON-protocol ReAct loop (works across cloud/ollama/custom without native function-calling support):

```
Round N:
  LLM returns text → parse JSON:
    {"type":"tool_call","tool":"file_read","args":{...}}   → execute, append result, continue
    {"type":"final","summary":string,"notes":[...]}        → terminate batch
  On parse failure → retry once with corrective message, then give up batch gracefully.
```

- `maxRounds` default 6 per batch; hard cap enforced.
- **Token budget**: estimate tokens per round from message lengths; per-batch budget derived from `maxTokensPerReview` (default 200k estimate) divided across batches; exceeding budget terminates the batch.
- `requestProviderCompletion` is reused for each round (single user message per round carrying the accumulated conversation JSON — keeps provider layer unchanged).
- System prompt instructs JSON protocol, tool schema, per-finding note schema, and language instructions (reuse existing `langInstruction`).

### 2c. Batched review

- Findings grouped by `category`, sorted by `riskLevel` (Critical→Info).
- Each batch runs an independent agent loop with isolated context (divide-and-conquer, alibaba-style).
- Batch size capped at `maxFindingsPerBatch` (default 10) — large batches split further.
- Each `AiReviewResult.findingNotes[i]` targets one finding id; batches merged into one `AiReviewResult`.
- Empty finding sets (no findings) short-circuit to a summary-only result without LLM calls.

### 2d. Integration

- `runAiReview(report, config, options?)` new signature: `options: { scanPath?: string; maxRounds?: number; maxFindingsPerBatch?: number; maxTokensPerReview?: number }`.
  - `scanPath` defaults to `report.target.localPath`.
  - When `scanPath` is unavailable (null) or mode is metadata-only, tools degrade to empty and the loop is single-shot.
- Electron `ai-review:run` handler passes `report.target.localPath` (no UI changes; renderer already receives `AiReviewResult`).
- CLI: if a review command exists, wire `scanPath` similarly (verify during implementation).
- `AiReviewResult` shape unchanged.

### 2e. Safety and testing

- `file_read`/`code_search` path traversal prevention (resolve + prefix check).
- `metadata-only` gating is enforced in code, not just prompt.
- Unit tests: tools (read, find, search, traversal rejection), loop (mock `FetchLike` with canned tool_call→final sequence, parse-failure retry, budget exhaustion), batching (grouping, caps, empty-findings short-circuit).
- Integration test: run full pipeline on `fixtures/malicious-package` with mocked provider.

## Data Flow (combined)

```
scanTarget(input)
  → resolveTarget → acquireRemoteTarget → scanPath
  → buildInventory(scanPath)             [Track 1: language-aware collectors]
  → runRules(inventory)                  [Track 1: path-filtered multi-language rules]
  → assessRisk → report (+ coverage)     [Track 1: coverage field]
  → renderOutputs
runAiReview(report, config, { scanPath })
  [Track 2: group findings → per-batch agent loop (tools gated by dataSharingMode)]
  → AiReviewResult { summary, findingNotes[] }
```

## Files Changed

Track 1:
- `packages/scanner-core/src/fileWalker.ts` — add `.py`/`.go`/`.java` extensions
- `packages/scanner-core/src/inventory.ts` — `DangerousCall`, `LanguageId`, language pattern table, collectors
- `packages/scanner-core/src/ruleTypes.ts` — `pathPattern` on `RuleDefinition`
- `packages/scanner-core/src/defaultRules.ts` — new built-in rules
- `packages/scanner-core/src/types.ts` — `ScanCoverage`, `AuditReport.coverage`
- `packages/scanner-core/src/scan.ts` — populate coverage
- `packages/scanner-core/src/reporters.ts` — coverage table in markdown/html
- `packages/scanner-core/src/i18n.ts` — new finding text translations
- `packages/scanner-core/src/index.ts` — export new types
- tests: `tests/inventory.test.ts`, `tests/rules.test.ts`, `tests/scan.test.ts`

Track 2:
- `packages/ai-review/src/tools.ts` — new
- `packages/ai-review/src/agent.ts` — new
- `packages/ai-review/src/review.ts` — runAiReview signature + orchestration
- `packages/ai-review/src/types.ts` — `AiReviewOptions`, batch types
- `packages/ai-review/src/index.ts` — export new modules
- `apps/electron/src/main.ts` — pass `target.localPath` to `runAiReview`
- tests: `packages/ai-review/tests/tools.test.ts`, `agent.test.ts` — new

## Out of Scope

- Session persistence/resume, web viewer, telemetry (alibaba features deferred).
- Native OpenAI/Anthropic function-calling (`tool_calls`); JSON protocol used instead for provider portability.
- `file_read_diff` (git-diff-based review); this tool scans full snapshots, not diffs.
- Concurrency across batches (sequenced for deterministic behavior in v1).
