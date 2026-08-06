# Per-Finding AI Deep-Dive Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an on-demand "AI 深入分析" button to each finding panel that runs a focused, tool-enabled single-finding agent loop and renders verdict + analysis + fix steps + corrected code inline (display-only).

**Architecture:** New `deepdive.ts` module in `packages/ai-review` builds a single-finding prompt and reuses the shared `runAgentLoop` (generalized with an optional custom `parseResponse`/`finalExample`, backward compatible). New `finding:review` IPC channel in the Electron app wires it to a per-finding renderer button. Results never write back into the report, decision, or export.

**Tech Stack:** TypeScript, Node 18+, Electron, Vitest, monorepo (npm workspaces: `@repo-auditor/ai-review`, `@repo-auditor/scanner-core`, `@repo-auditor/electron`).

**Spec:** `docs/superpowers/specs/2026-08-06-finding-deep-dive-design.md`

**Important context (read before starting):**
- The Electron app loads **compiled** `packages/*/dist/*.js`, not source. `npm run dev:electron` rebuilds `scanner-core` + `ai-review` first. After changing ai-review source, run `npm run build --workspace @repo-auditor/ai-review` before launching.
- Tests use Vitest. Commands per workspace: `npm test --workspace @repo-auditor/ai-review`, `npm test --workspace apps/electron`, typecheck `npm run typecheck --workspace @repo-auditor/<name>`.
- The electron `ipc.test.ts` is largely **source-inspection** (reads files, asserts string patterns) because `main.ts` imports Electron. Follow that style for IPC tests.
- `packages/ai-review/tests/review.test.ts` has a reusable `report`/`config` fixture; copy the shape (don't import — fixtures are per-file).
- Providers are fetched via injected `fetchImpl` in tests (`vi.fn` returning `{ ok, status, text: async () => "", json: async () => ({ choices: [{ message: { content } }] }) }`).

---

### Task 1: Generalize `runAgentLoop` for custom final schemas

**Files:**
- Modify: `packages/ai-review/src/agent.ts`
- Test: `packages/ai-review/tests/agent.test.ts`

Make the shared loop pluggable so `deepdive.ts` can reuse it with a different final schema, while keeping the batch path 100% backward compatible.

- [ ] **Step 1: Write the failing tests**

Append to `packages/ai-review/tests/agent.test.ts`:

```ts
describe("custom final schema via parseResponse + finalExample", () => {
  const ctx: ReviewToolContext = { scanPath: "", mode: "full-files" };

  it("builds prompts with a custom final schema example", () => {
    const prompt = buildAgentPrompt(
      "sys",
      [],
      ["initial"],
      '{"type":"final","verdict":"real|false-positive|uncertain","analysis":"...","fixSteps":[...],"correctedCode":"..."}'
    );
    expect(prompt).toContain('"verdict"');
    expect(prompt).not.toContain('"newFindings"');
  });

  it("returns a custom-shaped final result from a custom parser", async () => {
    const fetchImpl = jsonCompletion(
      JSON.stringify({ type: "final", verdict: "real", analysis: "confirmed", fixSteps: [], correctedCode: "" })
    );
    const result = await runAgentLoop(
      config,
      "system",
      "initial",
      [],
      ctx,
      {
        maxRounds: 1,
        maxTokensPerReview: 100000,
        parseResponse: (text: string) => {
          const parsed = JSON.parse(text) as Record<string, unknown>;
          if (parsed.type === "final") {
            return { type: "final", result: { verdict: String(parsed.verdict) } };
          }
          return undefined;
        },
        finalExample: '{"type":"final","verdict":"real"}'
      },
      fetchImpl
    );
    expect(result.result).toEqual({ verdict: "real" });
  });
});
```

`jsonCompletion` and `config` are module-level in `agent.test.ts`, so they are in scope here. Add this new `describe` at the **top level** of the file (outside the existing `describe("runAgentLoop", ...)` block); `ReviewToolContext` is already imported at the top of the file.

- [ ] **Step 2: Run tests to verify they fail**

Run: `npm test --workspace @repo-auditor/ai-review`
Expected: FAIL — `buildAgentPrompt`/`runAgentLoop` don't accept the new params (TS error), plus runtime failures.

- [ ] **Step 3: Implement the generalization in `agent.ts`**

Make these edits:

1. Extract the tool_call shape and expose helpers:
```ts
export interface ToolCallResponse {
  type: "tool_call";
  tool: string;
  args: Record<string, unknown>;
}
```

2. Make `AgentResponse`, `AgentLoopResult`, `AgentLoopOptions` generic and export `extractJsonObject`:
```ts
export type AgentResponse<TResult = AgentFinalResult> =
  | ToolCallResponse
  | { type: "final"; result: TResult }
  | undefined;

export interface AgentLoopResult<TResult = AgentFinalResult> {
  result?: TResult;
  raw: string;
}

export interface AgentLoopOptions<TResult = AgentFinalResult> {
  maxRounds: number;
  maxTokensPerReview: number;
  parseResponse?: (text: string) => AgentResponse<TResult>;
  finalExample?: string;
}
```
Change `function extractJsonObject(text: string): unknown {` to `export function extractJsonObject(text: string): unknown {`.

3. Add `parseToolCall` and refactor `parseAgentResponse` to use it:
```ts
export function parseToolCall(obj: Record<string, unknown>): ToolCallResponse | undefined {
  if (obj.type === "tool_call" && typeof obj.tool === "string") {
    return {
      type: "tool_call",
      tool: obj.tool,
      args: obj.args && typeof obj.args === "object" ? (obj.args as Record<string, unknown>) : {}
    };
  }
  return undefined;
}
```
Replace the final `if (obj.type === "tool_call" && typeof obj.tool === "string") { ... }` block at the end of `parseAgentResponse` with `return parseToolCall(obj);`.

4. `buildAgentPrompt` gains `finalExample?`:
```ts
export function buildAgentPrompt(
  systemPrompt: string,
  tools: ToolDefinition[],
  history: string[],
  finalExample?: string
): string {
  const toolList = tools.map((tool) => `- ${tool.name}: ${tool.description}`).join("\n");
  return [
    systemPrompt,
    "",
    "AVAILABLE TOOLS:",
    toolList || "- (none — respond with final immediately)",
    "",
    "CONVERSATION (most recent last):",
    ...history.map((entry, i) => `[${i + 1}]\n${entry}`),
    "",
    "RESPOND WITH A SINGLE JSON OBJECT:",
    finalExample ?? '{"type":"tool_call","tool":"<name>","args":{...}}  or  {"type":"final","summary":"...","notes":[...],"newFindings":[...]}',
    "Respond with only the JSON object, no surrounding text."
  ].join("\n");
}
```

5. `buildPromptWithinBudget` threads `finalExample`:
```ts
function buildPromptWithinBudget(
  systemPrompt: string,
  tools: ToolDefinition[],
  history: string[],
  budget: number,
  finalExample?: string
): string {
  let pruned = [...history];
  while (pruned.length > 1 && estimateTokens(buildAgentPrompt(systemPrompt, tools, pruned, finalExample)) > budget) {
    const idx = pruned.findIndex((entry) => entry.startsWith("<tool_result>"));
    if (idx === -1) {
      break;
    }
    pruned = pruned.slice(0, idx).concat(pruned.slice(idx + 1));
  }
  return buildAgentPrompt(systemPrompt, tools, pruned, finalExample);
}
```

6. `runAgentLoop` becomes generic:
```ts
export async function runAgentLoop<TResult = AgentFinalResult>(
  config: AiProviderConfig,
  systemPrompt: string,
  initialPrompt: string,
  tools: ToolDefinition[],
  ctx: ReviewToolContext,
  options: AgentLoopOptions<TResult>,
  fetchImpl?: FetchLike
): Promise<AgentLoopResult<TResult>> {
  const parseResponse =
    options.parseResponse ?? (parseAgentResponse as (text: string) => AgentResponse<TResult>);
  const history: string[] = [initialPrompt];
  let budget = resolveTokenBudget(config, options.maxTokensPerReview);
  let raw = "";

  for (let round = 0; round < options.maxRounds; round += 1) {
    const prompt = buildPromptWithinBudget(systemPrompt, tools, history, budget, options.finalExample);
    budget -= estimateTokens(prompt);
    if (budget <= 0) {
      break;
    }

    const response = await requestProviderCompletion(config, prompt, fetchImpl);
    raw = response;
    const parsed = parseResponse(response);

    if (parsed?.type === "final") {
      return { result: parsed.result, raw: response };
    }

    if (parsed?.type === "tool_call") {
      const tool = tools.find((t) => t.name === parsed.tool);
      let toolResult: string;
      if (!tool) {
        toolResult = `unknown tool "${parsed.tool}". Available: ${tools.map((t) => t.name).join(", ") || "(none)"}`;
      } else {
        try {
          toolResult = await tool.run(parsed.args, ctx);
        } catch (error) {
          toolResult = `tool error: ${error instanceof Error ? error.message : String(error)}`;
        }
      }
      budget -= estimateTokens(toolResult);
      history.push(`<assistant_json>${response}</assistant_json>`, `<tool_result>${toolResult}</tool_result>`);
      continue;
    }

    history.push(
      `<assistant>${response}</assistant>`,
      "<note>Your last response was not valid JSON. Respond with ONLY a JSON object: a tool_call or final.</note>"
    );
  }

  return { result: undefined, raw };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npm test --workspace @repo-auditor/ai-review`
Expected: PASS — new tests plus all existing agent + review tests.

- [ ] **Step 5: Commit**

```bash
git add packages/ai-review/src/agent.ts packages/ai-review/tests/agent.test.ts
git commit -m "feat(ai-review): generalize runAgentLoop for custom final schemas
Adds optional parseResponse and finalExample to AgentLoopOptions, defaulting
to the existing batch parser so behavior is unchanged. Extracts parseToolCall
and exports extractJsonObject for reuse by deep-dive."
```

---

### Task 2: `deepdive.ts` — parser and prompt builders

**Files:**
- Create: `packages/ai-review/src/deepdive.ts`
- Test: `packages/ai-review/tests/deepdive.test.ts`

- [ ] **Step 1: Write the failing parser + prompt tests**

Create `packages/ai-review/tests/deepdive.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { buildDeepDivePrompt, parseDeepDiveResponse } from "../src/deepdive.js";
import type { AiProviderConfig } from "../src/types.js";
import type { AuditReport, Finding } from "@repo-auditor/scanner-core";

const config: AiProviderConfig = {
  type: "cloud",
  baseUrl: "https://api.example.test/v1",
  model: "gpt-test",
  dataSharingMode: "full-files",
  redactionEnabled: true,
  timeoutMs: 30000,
  retryLimit: 0
};

const finding: Finding = {
  id: "finding-1",
  riskLevel: "High",
  category: "network",
  filePath: "src/index.ts",
  lineStart: 1,
  lineEnd: 1,
  codeSnippet: "const token = '123456:ABCdefSecretValueABCdefSecretValue'; fetch('https://evil.example')",
  explanation: "network exfiltration candidate",
  recommendedFix: "Remove sensitive payloads from outbound requests.",
  evidenceTags: ["network-endpoint", "exfiltration-candidate"],
  confidence: "High"
};

const report: AuditReport = {
  target: {
    type: "local-directory",
    source: "fixture",
    localPath: "fixture",
    provenance: { source: "fixture" },
    networkUsed: false,
    trustBoundary: "local"
  },
  findings: [finding],
  dataFlow: { nodes: [], edges: [] },
  attackSurface: [],
  risk: {
    overallRiskLevel: "High",
    decision: "Block",
    rationale: "blocking finding",
    topRisks: ["High: network exfiltration candidate"],
    severityCounts: { Critical: 0, High: 1, Medium: 0, Low: 0, Info: 0 },
    categoryCounts: { network: 1 },
    blockingFindingIds: ["finding-1"],
    residualRisk: "static only",
    scanLimitations: ["static analysis only"]
  },
  generatedAt: "2026-06-14T00:00:00.000Z",
  toolVersion: "0.1.0"
};

describe("parseDeepDiveResponse", () => {
  it("parses a full valid deep-dive final", () => {
    const parsed = parseDeepDiveResponse(
      JSON.stringify({
        type: "final",
        verdict: "real",
        analysis: "The token is sent to an external endpoint",
        fixSteps: ["Remove the fetch call", "Move secrets to env"],
        correctedCode: "fetch(url, { headers })"
      })
    );
    expect(parsed?.type).toBe("final");
    if (parsed?.type === "final") {
      expect(parsed.result.verdict).toBe("real");
      expect(parsed.result.analysis).toContain("external endpoint");
      expect(parsed.result.fixSteps).toHaveLength(2);
      expect(parsed.result.correctedCode).toBe("fetch(url, { headers })");
    }
  });

  it("normalizes verdict aliases", () => {
    const pick = (text: string) => {
      const parsed = parseDeepDiveResponse(text);
      return parsed?.type === "final" ? parsed.result.verdict : undefined;
    };
    expect(pick(JSON.stringify({ type: "final", verdict: "vulnerable" }))).toBe("real");
    expect(pick(JSON.stringify({ type: "final", verdict: "true" }))).toBe("real");
    expect(pick(JSON.stringify({ type: "final", verdict: "false" }))).toBe("false-positive");
    expect(pick(JSON.stringify({ type: "final", verdict: "not-an-issue" }))).toBe("false-positive");
    expect(pick(JSON.stringify({ type: "final", verdict: "maybe" }))).toBe("uncertain");
    expect(pick(JSON.stringify({ type: "final" }))).toBe("uncertain");
  });

  it("normalizes analysis and correctedCode key aliases", () => {
    const parsed = parseDeepDiveResponse(
      JSON.stringify({ type: "final", verdict: "real", detail: "deeper detail", patch: "git diff content" })
    );
    if (parsed?.type === "final") {
      expect(parsed.result.analysis).toBe("deeper detail");
      expect(parsed.result.correctedCode).toBe("git diff content");
    }
  });

  it("splits string fixSteps on newlines", () => {
    const parsed = parseDeepDiveResponse(
      JSON.stringify({ type: "final", verdict: "real", steps: "first\nsecond" })
    );
    if (parsed?.type === "final") {
      expect(parsed.result.fixSteps).toEqual(["first", "second"]);
    }
  });

  it("passes tool calls through", () => {
    const parsed = parseDeepDiveResponse(
      JSON.stringify({ type: "tool_call", tool: "file_read", args: { path: "src/index.ts" } })
    );
    expect(parsed?.type).toBe("tool_call");
    if (parsed?.type === "tool_call") {
      expect(parsed.tool).toBe("file_read");
    }
  });

  it("returns undefined for non-JSON text", () => {
    expect(parseDeepDiveResponse("plain text")).toBeUndefined();
  });
});

describe("buildDeepDivePrompt", () => {
  it("includes the finding and omits snippets in metadata-only mode", () => {
    const prompt = buildDeepDivePrompt(finding, report, { ...config, dataSharingMode: "metadata-only" });
    expect(prompt).toContain("src/index.ts");
    expect(prompt).not.toContain("ABCdefSecretValue");
  });

  it("redacts secrets when snippets are shared", () => {
    const prompt = buildDeepDivePrompt(finding, report, { ...config, dataSharingMode: "finding-snippets" });
    expect(prompt).toContain("[REDACTED_TELEGRAM_TOKEN]");
    expect(prompt).not.toContain("ABCdefSecretValue");
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npm test --workspace @repo-auditor/ai-review`
Expected: FAIL — `deepdive.js` module doesn't exist.

- [ ] **Step 3: Implement parser + prompt builders**

Create `packages/ai-review/src/deepdive.ts`:

```ts
import type { Finding, AuditReport } from "@repo-auditor/scanner-core";
import { extractJsonObject, parseToolCall, type AgentResponse } from "./agent.js";
import { serializeFindingForPrompt } from "./review.js";
import { redactSecrets } from "./redaction.js";
import type { AiProviderConfig } from "./types.js";

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

function normalizeVerdict(value: unknown): DeepDiveVerdict {
  if (typeof value !== "string") {
    return "uncertain";
  }
  const v = value.trim().toLowerCase();
  if (["real", "vulnerable", "true", "confirmed"].includes(v)) {
    return "real";
  }
  if (["false-positive", "false", "benign", "not-an-issue"].includes(v)) {
    return "false-positive";
  }
  return "uncertain";
}

function normalizeStringList(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.filter((entry): entry is string => typeof entry === "string");
  }
  if (typeof value === "string") {
    return value
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
  }
  return [];
}

export function parseDeepDiveResponse(text: string): AgentResponse<DeepDiveResult> {
  const parsed = extractJsonObject(text);
  if (!parsed || typeof parsed !== "object") {
    return undefined;
  }
  const obj = parsed as Record<string, unknown>;
  const toolCall = parseToolCall(obj);
  if (toolCall) {
    return toolCall;
  }
  if (obj.type === "final") {
    const analysis =
      ["analysis", "detail", "explanation"].map((key) => obj[key]).find((value) => typeof value === "string") ?? "";
    const fixSteps =
      ["fixSteps", "steps", "recommendations"].map((key) => obj[key]).find((value) => value !== undefined) ?? [];
    const correctedCode =
      ["correctedCode", "code", "patch"].map((key) => obj[key]).find((value) => typeof value === "string") ?? "";
    return {
      type: "final",
      result: {
        verdict: normalizeVerdict(obj.verdict),
        analysis,
        fixSteps: normalizeStringList(fixSteps),
        correctedCode
      }
    };
  }
  return undefined;
}

export function buildDeepDiveSystemPrompt(config: AiProviderConfig): string {
  const toolGuidance =
    config.dataSharingMode === "metadata-only"
      ? "No tools are available. Base your verdict only on the provided finding metadata."
      : "Read files and search code before concluding. Verify the finding against real code.";
  return [
    "You are a focused security code-review agent.",
    toolGuidance,
    "Respond ONLY with a single JSON object: either a tool_call or a final result with the deep-dive schema."
  ].join("\n");
}

export const DEEP_DIVE_FINAL_EXAMPLE =
  '{"type":"tool_call","tool":"<name>","args":{...}}  or  {"type":"final","verdict":"real|false-positive|uncertain","analysis":"...","fixSteps":[...],"correctedCode":"..."}';

export function buildDeepDivePrompt(finding: Finding, report: AuditReport, config: AiProviderConfig): string {
  const langInstruction: Record<string, string> = {
    en: "You MUST respond in English.",
    "zh-TW": "你必須使用繁體中文回覆。",
    "zh-CN": "你必须使用简体中文回复。"
  };
  const lang = config.language ?? "zh-TW";
  const range =
    finding.lineEnd > finding.lineStart ? `${finding.lineStart}-${finding.lineEnd}` : String(finding.lineStart);
  const findingJson = JSON.stringify(serializeFindingForPrompt(finding, config), null, 2);
  const prompt = [
    "You are analyzing a single deterministic security finding in depth.",
    "Read the actual source code with the available tools to verify the evidence before concluding.",
    `Finding is at ${finding.filePath}:${range}.`,
    "Decide the verdict based on verified evidence. If the finding is real, provide concrete step-by-step fix steps and a corrected code snippet.",
    langInstruction[lang] ?? langInstruction["zh-TW"],
    "",
    "FINDING:",
    findingJson
  ].join("\n");

  return config.redactionEnabled ? redactSecrets(prompt) : prompt;
}
```

- [ ] **Step 4: Export `serializeFindingForPrompt` from `review.ts`**

In `packages/ai-review/src/review.ts`, change `function serializeFindingForPrompt(finding: Finding, config: AiProviderConfig) {` to `export function serializeFindingForPrompt(finding: Finding, config: AiProviderConfig) {`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `npm test --workspace @repo-auditor/ai-review`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add packages/ai-review/src/deepdive.ts packages/ai-review/src/review.ts packages/ai-review/tests/deepdive.test.ts
git commit -m "feat(ai-review): add deep-dive parser and single-finding prompt builders"
```

---

### Task 3: `deepdive.ts` — `runDeepDive`

**Files:**
- Modify: `packages/ai-review/src/deepdive.ts`
- Test: `packages/ai-review/tests/deepdive.test.ts`

- [ ] **Step 1: Write the failing `runDeepDive` tests**

Append to `packages/ai-review/tests/deepdive.test.ts` (add `vi` to the existing import from `vitest`):

```ts
import { runDeepDive } from "../src/deepdive.js";
```

```ts
describe("runDeepDive", () => {
  function jsonCompletion(content: string) {
    return vi.fn(async () => ({
      ok: true,
      status: 200,
      text: async () => "",
      json: async () => ({ choices: [{ message: { content } }] })
    }));
  }

  it("returns a parsed deep-dive result", async () => {
    const fetchImpl = jsonCompletion(
      JSON.stringify({
        type: "final",
        verdict: "real",
        analysis: "confirmed",
        fixSteps: ["step one"],
        correctedCode: "code"
      })
    );
    const result = await runDeepDive(finding, report, config, { scanPath: "fixture", maxRounds: 1 }, fetchImpl);
    expect(result.result?.verdict).toBe("real");
    expect(result.result?.analysis).toBe("confirmed");
    expect(result.truncated).toBe(false);
  });

  it("returns truncated when the provider request is aborted", async () => {
    const aborted = Object.assign(new Error("This operation was aborted"), { name: "AbortError" });
    const fetchImpl = vi.fn(async () => {
      throw aborted;
    });
    const result = await runDeepDive(finding, report, config, { scanPath: "fixture", maxRounds: 1 }, fetchImpl);
    expect(result.truncated).toBe(true);
    expect(result.result).toBeUndefined();
  });

  it("preserves raw text when the model never emits valid JSON", async () => {
    const fetchImpl = jsonCompletion("plain text");
    const result = await runDeepDive(finding, report, config, { scanPath: "fixture", maxRounds: 2 }, fetchImpl);
    expect(result.result).toBeUndefined();
    expect(result.truncated).toBe(false);
    expect(result.raw).toBe("plain text");
  });

  it("executes tool calls before producing a final result", async () => {
    const fetchTool = jsonCompletion(
      JSON.stringify({ type: "tool_call", tool: "file_read", args: { path: "src/index.ts" } })
    );
    const fetchFinal = jsonCompletion(
      JSON.stringify({ type: "final", verdict: "false-positive", analysis: "ok", fixSteps: [], correctedCode: "" })
    );
    let callCount = 0;
    const fetchImpl = vi.fn(async (...args: Parameters<typeof fetchFinal>) => {
      callCount += 1;
      return callCount === 1 ? await fetchTool(...args) : await fetchFinal(...args);
    });
    const result = await runDeepDive(finding, report, config, { scanPath: "fixture", maxRounds: 3 }, fetchImpl);
    expect(result.result?.verdict).toBe("false-positive");
    expect(callCount).toBeGreaterThanOrEqual(2);
  });
});
```

Note: the tool test relies on `file_read` returning a graceful "not a file" error string when `fixture/src/index.ts` does not exist (it does — the tool catches `fs.stat` failure), so the loop continues to the final round.

- [ ] **Step 2: Run tests to verify they fail**

Run: `npm test --workspace @repo-auditor/ai-review`
Expected: FAIL — `runDeepDive` not exported.

- [ ] **Step 3: Implement `runDeepDive`**

Append to `packages/ai-review/src/deepdive.ts`:

```ts
import { runAgentLoop } from "./agent.js";
import { buildTools, type ReviewToolContext } from "./tools.js";
import type { FetchLike } from "./providers.js";

export async function runDeepDive(
  finding: Finding,
  report: AuditReport,
  config: AiProviderConfig,
  options: DeepDiveOptions = {},
  fetchImpl?: FetchLike
): Promise<DeepDiveRunResult> {
  const scanPath = options.scanPath ?? report.target.localPath ?? "";
  const mode: ReviewToolContext["mode"] = config.dataSharingMode === "full-files" ? "full-files" : "snippets";
  const ctx: ReviewToolContext = {
    scanPath,
    mode,
    allowedFiles: config.dataSharingMode === "finding-snippets" ? [finding.filePath] : undefined
  };
  const tools = buildTools(config.dataSharingMode, ctx);

  try {
    const loopResult = await runAgentLoop(
      config,
      buildDeepDiveSystemPrompt(config),
      buildDeepDivePrompt(finding, report, config),
      tools,
      ctx,
      {
        maxRounds: options.maxRounds ?? 6,
        maxTokensPerReview: options.maxTokensPerReview ?? 30_000,
        parseResponse: parseDeepDiveResponse,
        finalExample: DEEP_DIVE_FINAL_EXAMPLE
      },
      fetchImpl
    );
    return { result: loopResult.result, raw: loopResult.raw, truncated: false };
  } catch {
    return { result: undefined, raw: "", truncated: true };
  }
}
```

Merge the new imports with the existing top-of-file imports (keep them grouped; the file already imports `extractJsonObject`, `parseToolCall`, `AgentResponse` from `./agent.js` — add `runAgentLoop` to that import).

- [ ] **Step 4: Run tests to verify they pass**

Run: `npm test --workspace @repo-auditor/ai-review`
Expected: PASS — all deepdive tests (parser, prompt, runDeepDive) and the rest of the suite.

- [ ] **Step 5: Commit**

```bash
git add packages/ai-review/src/deepdive.ts packages/ai-review/tests/deepdive.test.ts
git commit -m "feat(ai-review): run a tool-enabled single-finding deep-dive agent loop
Aborts degrade to truncated:true, parse failures preserve raw text, mirroring
the batch review contract."
```

---

### Task 4: Export the deep-dive API from the package entry

**Files:**
- Modify: `packages/ai-review/src/index.ts`

- [ ] **Step 1: Add exports**

In `packages/ai-review/src/index.ts` append:

```ts
export { buildDeepDivePrompt, buildDeepDiveSystemPrompt, parseDeepDiveResponse, runDeepDive } from "./deepdive.js";
export type { DeepDiveOptions, DeepDiveResult, DeepDiveRunResult, DeepDiveVerdict } from "./deepdive.js";
```

Also export the new shared helpers from `./agent.js` (used by deepdive and potentially consumers):
Change the existing agent export line to:
```ts
export { buildAgentPrompt, estimateTokens, extractJsonObject, parseAgentResponse, parseToolCall, resolveTokenBudget, runAgentLoop } from "./agent.js";
export type { AgentFinalResult, AgentLoopOptions, AgentLoopResult, AgentNote, ToolCallResponse } from "./agent.js";
```

- [ ] **Step 2: Typecheck + build**

Run: `npm run typecheck --workspace @repo-auditor/ai-review && npm run build --workspace @repo-auditor/ai-review`
Expected: clean typecheck; `dist/deepdive.js` exists.

- [ ] **Step 3: Commit**

```bash
git add packages/ai-review/src/index.ts
git commit -m "feat(ai-review): export deep-dive API and shared agent helpers"
```

---

### Task 5: Electron IPC — `finding:review` channel

**Files:**
- Modify: `apps/electron/src/ipc.ts`
- Modify: `apps/electron/src/preload.ts`
- Modify: `apps/electron/src/main.ts`
- Test: `apps/electron/tests/ipc.test.ts`

- [ ] **Step 1: Update the failing tests**

In `apps/electron/tests/ipc.test.ts`:

1. Update the exact-array allowlist assertion (lines 9-25) to include `"finding:review"` after `"ai-review:run"`:

```ts
    expect(allowedIpcChannels).toEqual([
      "scan:start",
      "scan:cancel",
      "report:read",
      "report:export",
      "ai-review:run",
      "finding:review",
      "ai-review:progress",
      "ai-models:list",
      "ai-connection:test",
      "folder:open",
      "rules:load",
      "rules:save",
      "key:save",
      "key:load",
      "key:delete",
      "source:read"
    ]);
```

2. Append new source-inspection tests to the "main window lifecycle" describe:

```ts
  it("keeps finding:review in the IPC allowlist", () => {
    expect(isAllowedIpcChannel("finding:review")).toBe(true);
  });

  it("registers the finding:review handler and lazy-loads runDeepDive", () => {
    const source = fs.readFileSync(path.join(__dirname, "../src/main.ts"), "utf8");

    expect(source).toContain('ipcMain.handle("finding:review"');
    expect(source).toContain('assertAllowed("finding:review")');
    expect(source).toContain("runDeepDive(");
    expect(source).toContain("scanPath: payload.report.target.localPath ?? undefined");
  });
```

(The renderer wiring assertion is added in Task 6, where the renderer is modified.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `npm test --workspace apps/electron`
Expected: FAIL — allowlist missing `finding:review`, `main.ts` has no handler, renderer has no deep-dive wiring.

- [ ] **Step 3: Add the channel to `ipc.ts`**

In `apps/electron/src/ipc.ts`, add `"finding:review",` after `"ai-review:run",` in the `allowedIpcChannels` array.

- [ ] **Step 4: Add preload exposure in `preload.ts`**

In `apps/electron/src/preload.ts`:
- Add `| "finding:review"` to the `AllowedIpcChannel` union after `"ai-review:run"`.
- Add `findingReview: (payload: unknown) => invoke("finding:review", payload),` after the `aiReviewRun` line.

- [ ] **Step 5: Add the handler in `main.ts`**

1. Add `Finding` to the scanner-core type import (line 4):
```ts
import type { AuditReport, Finding, Language, NetworkPolicy, OutputFormat } from "@repo-auditor/scanner-core";
```

2. Add a payload interface after `AiReviewPayload` (line 27):
```ts
interface FindingReviewPayload {
  finding: Finding;
  report: AuditReport;
  provider: AiProviderConfig;
  language?: Language;
}
```

3. Add the handler immediately after the `ai-review:run` handler (after line 227):
```ts
ipcMain.handle("finding:review", async (_event, payload: FindingReviewPayload) => {
  assertAllowed("finding:review");
  const finding = payload?.finding;
  if (!finding || typeof finding.id !== "string" || typeof finding.filePath !== "string") {
    return { error: "A valid finding is required" };
  }
  const { runDeepDive } = await import("@repo-auditor/ai-review");
  const provider = {
    ...payload.provider,
    language: payload.provider.language ?? "zh-TW",
    redactionEnabled: true,
    timeoutMs: 120000,
    retryLimit: 1
  };
  return runDeepDive(finding, payload.report, provider, {
    scanPath: payload.report.target.localPath ?? undefined
  });
});
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `npm test --workspace apps/electron`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add apps/electron/src/ipc.ts apps/electron/src/preload.ts apps/electron/src/main.ts apps/electron/tests/ipc.test.ts
git commit -m "feat(electron): add finding:review IPC channel for per-finding deep dives"
```

---

### Task 6: Renderer — deep-dive button and inline result

**Files:**
- Modify: `apps/electron/src/renderer/index.html`
- Test: `apps/electron/tests/ipc.test.ts` (already updated in Task 5)

- [ ] **Step 1: Add the failing renderer assertion test**

In `apps/electron/tests/ipc.test.ts`, append to the "main window lifecycle" describe:

```ts
  it("adds per-finding deep-dive controls to the renderer", () => {
    const source = fs.readFileSync(path.join(__dirname, "../src/renderer/index.html"), "utf8");

    expect(source).toContain("window.repoAuditor.findingReview");
    expect(source).toContain('t("aiDeepDive")');
    expect(source).toContain("aiVerdictReal");
  });
```

Run `npm test --workspace apps/electron` — expected FAIL (renderer not wired yet).

- [ ] **Step 2: Add i18n keys**

In the `ui` object add these keys to all three languages (`en`, `zh-TW`, `zh-CN`) right after the existing `aiBatchProgress` key:

`en`:
```js
aiDeepDive: "AI Deep-Dive",
aiDeepDiveReviewing: "Deep-diving...",
aiDeepDiveFailed: "Deep-dive failed",
aiDeepDiveTruncated: "The provider was interrupted; showing the raw response.",
aiVerdictReal: "Real vulnerability",
aiVerdictFalsePositive: "False positive",
aiVerdictUncertain: "Cannot determine",
aiAnalysis: "Analysis",
aiFixSteps: "Fix steps",
aiCorrectedCode: "Corrected code"
```

`zh-TW`:
```js
aiDeepDive: "AI 深入分析",
aiDeepDiveReviewing: "深入分析中...",
aiDeepDiveFailed: "深入分析失敗",
aiDeepDiveTruncated: "提供者連線中斷；顯示原始回應。",
aiVerdictReal: "真實漏洞",
aiVerdictFalsePositive: "誤報",
aiVerdictUncertain: "無法確定",
aiAnalysis: "分析",
aiFixSteps: "修復步驟",
aiCorrectedCode: "修正程式碼"
```

`zh-CN`:
```js
aiDeepDive: "AI 深入分析",
aiDeepDiveReviewing: "深入分析中...",
aiDeepDiveFailed: "深入分析失败",
aiDeepDiveTruncated: "提供商连接中断；显示原始响应。",
aiVerdictReal: "真实漏洞",
aiVerdictFalsePositive: "误报",
aiVerdictUncertain: "无法确定",
aiAnalysis: "分析",
aiFixSteps: "修复步骤",
aiCorrectedCode: "修正代码"
```

- [ ] **Step 3: Add the button and handler in `renderResult`**

In the `renderResult` per-finding `detail` construction, immediately after the existing `detail.appendChild(ctxBtn);` line, add:

```js
            const diveBtn = document.createElement("button");
            diveBtn.className = "secondary";
            diveBtn.textContent = t("aiDeepDive");
            diveBtn.addEventListener("click", async (e) => {
              e.stopPropagation();
              diveBtn.disabled = true;
              diveBtn.textContent = t("aiDeepDiveReviewing");
              const out = document.createElement("div");
              out.className = "finding-dive";
              detail.appendChild(out);
              try {
                const res = await window.repoAuditor.findingReview({
                  finding,
                  report: state.result.report,
                  provider: {
                    type: $("provider-type").value,
                    baseUrl: $("provider-url").value,
                    model: $("provider-model").value,
                    apiKey: $("provider-api-key").value || undefined,
                    dataSharingMode: $("sharing-mode").value,
                    redactionEnabled: true,
                    timeoutMs: 120000,
                    retryLimit: 1
                  },
                  language: currentLang()
                });
                if (res.error) {
                  out.className = "hint error finding-dive";
                  out.textContent = `${t("aiDeepDiveFailed")}: ${res.error}`;
                  return;
                }
                if (!res.result) {
                  const note = document.createElement("p");
                  note.className = "muted";
                  note.textContent = res.truncated ? t("aiDeepDiveTruncated") : t("aiDeepDiveFailed");
                  out.appendChild(note);
                  const pre = document.createElement("pre");
                  pre.className = "finding-patch";
                  pre.textContent = res.raw || "-";
                  out.appendChild(pre);
                  return;
                }
                const result = res.result;
                const verdictLabels = {
                  real: t("aiVerdictReal"),
                  "false-positive": t("aiVerdictFalsePositive"),
                  uncertain: t("aiVerdictUncertain")
                };
                const verdictColors = { real: "#d1242f", "false-positive": "#2da44e", uncertain: "#6c757d" };
                const verdictEl = document.createElement("p");
                verdictEl.innerHTML = `<strong style="color:${verdictColors[result.verdict] || "#6c757d"}">${verdictLabels[result.verdict] || result.verdict}</strong>`;
                out.appendChild(verdictEl);
                const analysisEl = document.createElement("p");
                analysisEl.textContent = result.analysis;
                out.appendChild(analysisEl);
                if (result.fixSteps.length > 0) {
                  const h4 = document.createElement("h4");
                  h4.textContent = t("aiFixSteps");
                  out.appendChild(h4);
                  const ol = document.createElement("ol");
                  result.fixSteps.forEach((step) => {
                    const li = document.createElement("li");
                    li.textContent = step;
                    ol.appendChild(li);
                  });
                  out.appendChild(ol);
                }
                if (result.correctedCode) {
                  const h4 = document.createElement("h4");
                  h4.textContent = t("aiCorrectedCode");
                  out.appendChild(h4);
                  const pre = document.createElement("pre");
                  pre.className = "finding-patch";
                  pre.textContent = result.correctedCode;
                  out.appendChild(pre);
                }
              } catch (error) {
                out.className = "hint error finding-dive";
                out.textContent = `${t("aiDeepDiveFailed")}: ${error instanceof Error ? error.message : "unknown error"}`;
              } finally {
                diveBtn.disabled = false;
                diveBtn.textContent = t("aiDeepDive");
              }
            });
            detail.appendChild(diveBtn);
```

- [ ] **Step 4: Add minimal CSS**

In the `<style>` block, right after the `.finding-fix { margin: 4px 0; }` rule, add:

```css
      .finding-dive { margin-top: 8px; padding-top: 8px; border-top: 1px solid #d0d7de; }
      .finding-dive h4 { margin: 8px 0 4px; }
```

- [ ] **Step 5: Validate the inline script syntax**

Run:
```bash
python3 - <<'EOF'
import re
html = open("apps/electron/src/renderer/index.html").read()
scripts = re.findall(r'<script(?:\s[^>]*)?>(.*?)</script>', html, re.S)
for i, s in enumerate(scripts):
    open(f"/tmp/renderer_script_{i}.js", "w").write(s)
    print(i, len(s))
EOF
node --check /tmp/renderer_script_0.js
```
Expected: `node --check` prints nothing (no syntax errors) and exits 0.

- [ ] **Step 6: Run electron tests**

Run: `npm test --workspace apps/electron`
Expected: PASS (includes the renderer assertions added in Step 1).

- [ ] **Step 7: Commit**

```bash
git add apps/electron/src/renderer/index.html
git commit -m "feat(electron): add per-finding AI deep-dive button and inline results"
```

---

### Task 7: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Run the full test suite**

Run: `npm test`
Expected: `Test Files  19 passed (19)` / `Tests  <all> passed`. The ai-review suite grows by the deepdive tests; the electron suite by the new IPC assertions.

- [ ] **Step 2: Typecheck every workspace**

Run: `npm run typecheck --workspace @repo-auditor/ai-review && npm run typecheck --workspace @repo-auditor/scanner-core && npm run typecheck --workspace @repo-auditor/cli && npm run typecheck --workspace apps/electron`
Expected: all clean.

- [ ] **Step 3: Rebuild the packages the app loads**

Run: `npm run build --workspace @repo-auditor/ai-review && npm run build --workspace apps/electron`
Expected: builds; `packages/ai-review/dist/deepdive.js` exists and contains `runDeepDive`.

- [ ] **Step 4: Smoke-test the deep-dive via the CLI-adjacent API**

Run a quick node check that the compiled dist exposes the new API (the package is `"type": "module"`, so use a dynamic import, not `require`):
```bash
node -e "import('./packages/ai-review/dist/deepdive.js').then(m => console.log(typeof m.runDeepDive, typeof m.parseDeepDiveResponse)).catch(e => { console.error(e); process.exit(1); })"
```
Expected: `function function`.

- [ ] **Step 5: Commit any remaining changes**

```bash
git status
git add -A
git commit -m "chore: verify per-finding deep-dive end to end"
```
(If nothing is pending, skip the commit.)

**Done.** Tell the user to relaunch with `npm run dev:electron` and click「AI 深入分析」on a finding.
