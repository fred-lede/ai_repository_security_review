import { requestProviderCompletion, type FetchLike } from "./providers.js";
import type { ToolDefinition, ReviewToolContext } from "./tools.js";
import type { AiProviderConfig } from "./types.js";

export interface AgentNote {
  findingId: string;
  explanation: string;
  falsePositiveNote?: string;
  saferPattern?: string;
}

export interface AgentFinalResult {
  summary: string;
  notes: AgentNote[];
}

export interface AgentLoopResult {
  result?: AgentFinalResult;
  raw: string;
}

export interface AgentLoopOptions {
  maxRounds: number;
  maxTokensPerReview: number;
}

export function estimateTokens(text: string): number {
  return Math.max(1, Math.ceil(text.length / 4));
}

function extractJsonObject(text: string): unknown {
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

export type AgentResponse =
  | { type: "tool_call"; tool: string; args: Record<string, unknown> }
  | { type: "final"; result: AgentFinalResult }
  | undefined;

export function parseAgentResponse(text: string): AgentResponse {
  const parsed = extractJsonObject(text);
  if (!parsed || typeof parsed !== "object") {
    return undefined;
  }

  const obj = parsed as Record<string, unknown>;

  if (obj.type === "final") {
    const notes = Array.isArray(obj.notes)
      ? (obj.notes as AgentNote[]).filter((n) => n && typeof n.findingId === "string")
      : [];
    return {
      type: "final",
      result: {
        summary: typeof obj.summary === "string" ? obj.summary : "",
        notes
      }
    };
  }

  if (obj.type === "tool_call" && typeof obj.tool === "string") {
    return {
      type: "tool_call",
      tool: obj.tool,
      args: obj.args && typeof obj.args === "object" ? (obj.args as Record<string, unknown>) : {}
    };
  }

  return undefined;
}

export function buildAgentPrompt(
  systemPrompt: string,
  tools: ToolDefinition[],
  history: string[]
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
    '{"type":"tool_call","tool":"<name>","args":{...}}  or  {"type":"final","summary":"...","notes":[{"findingId":"...","explanation":"...","falsePositiveNote":"...","saferPattern":"..."}]}',
    "Respond with only the JSON object, no surrounding text."
  ].join("\n");
}

export async function runAgentLoop(
  config: AiProviderConfig,
  systemPrompt: string,
  initialPrompt: string,
  tools: ToolDefinition[],
  ctx: ReviewToolContext,
  options: AgentLoopOptions,
  fetchImpl?: FetchLike
): Promise<AgentLoopResult> {
  const history: string[] = [initialPrompt];
  let budget = options.maxTokensPerReview;
  let raw = "";

  for (let round = 0; round < options.maxRounds; round += 1) {
    const prompt = buildAgentPrompt(systemPrompt, tools, history);
    budget -= estimateTokens(prompt);
    if (budget <= 0) {
      break;
    }

    const response = await requestProviderCompletion(config, prompt, fetchImpl);
    raw = response;
    const parsed = parseAgentResponse(response);

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
