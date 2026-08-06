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
