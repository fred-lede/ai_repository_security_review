import { requestProviderCompletion, type FetchLike } from "./providers.js";
import type { ToolDefinition, ReviewToolContext } from "./tools.js";
import type { AiNewFinding, AiProviderConfig } from "./types.js";

export interface AgentNote {
  findingId: string;
  explanation: string;
  falsePositiveNote?: string;
  saferPattern?: string;
}

export interface AgentFinalResult {
  summary: string;
  notes: AgentNote[];
  newFindings: AiNewFinding[];
}

export interface ToolCallResponse {
  type: "tool_call";
  tool: string;
  args: Record<string, unknown>;
}

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

export function estimateTokens(text: string): number {
  return Math.max(1, Math.ceil(text.length / 4));
}

export function extractJsonObject(text: string): unknown {
  const trimmed = text.trim();
  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/);
  const candidate = fenced ? fenced[1].trim() : trimmed;

  try {
    return JSON.parse(candidate);
  } catch {
    const start = candidate.indexOf("{");
    const end = candidate.lastIndexOf("}");
    if (start >= 0 && end > start) {
      try {
        return JSON.parse(candidate.slice(start, end + 1));
      } catch {
        return undefined;
      }
    }
    return undefined;
  }
}

export type AgentResponse<TResult = AgentFinalResult> =
  | ToolCallResponse
  | { type: "final"; result: TResult }
  | undefined;

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

export function parseAgentResponse(text: string): AgentResponse {
  const parsed = extractJsonObject(text);
  if (!parsed || typeof parsed !== "object") {
    return undefined;
  }

  const obj = parsed as Record<string, unknown>;

  if (obj.type === "final") {
    const notes = Array.isArray(obj.notes)
      ? (obj.notes as Array<Record<string, unknown>>)
          .map(normalizeNote)
          .filter((n): n is AgentNote => Boolean(n))
      : [];
    const newFindings = Array.isArray(obj.newFindings)
      ? (obj.newFindings as AiNewFinding[]).filter(
          (nf) =>
            nf &&
            typeof nf === "object" &&
            typeof nf.category === "string" &&
            typeof nf.filePath === "string" &&
            typeof nf.codeSnippet === "string" &&
            typeof nf.explanation === "string" &&
            typeof nf.lineStart === "number" &&
            typeof nf.lineEnd === "number" &&
            typeof nf.recommendedFix === "string"
        )
      : [];
    return {
      type: "final",
      result: {
        summary: typeof obj.summary === "string" ? obj.summary : "",
        notes,
        newFindings
      }
    };
  }

  return parseToolCall(obj);
}

const noteIdKeys = ["findingId", "finding_id", "findingID", "id", "finding-id"] as const;

function normalizeNote(raw: unknown): AgentNote | undefined {
  if (!raw || typeof raw !== "object") {
    return undefined;
  }
  const note = raw as Record<string, unknown>;
  const findingId = noteIdKeys.map((key) => note[key]).find((value) => typeof value === "string");
  if (typeof findingId !== "string") {
    return undefined;
  }
  const text = (key: string, fallback = "") => (typeof note[key] === "string" ? (note[key] as string) : fallback);
  return {
    findingId,
    explanation: text("explanation"),
    falsePositiveNote: text("falsePositiveNote", undefined),
    saferPattern: text("saferPattern", undefined)
  };
}

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

export function resolveTokenBudget(config: AiProviderConfig, maxTokensPerReview: number): number {
  const contextWindow = config.contextWindow ?? (config.type === "ollama" ? 32768 : 131072);
  const safeTokensPerReview = typeof maxTokensPerReview === "number" && maxTokensPerReview > 0 ? maxTokensPerReview : 2000;
  return Math.max(2000, Math.min(safeTokensPerReview, Math.floor(contextWindow * 0.7)));
}

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
