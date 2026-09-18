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

function normalizeVerdict(value: unknown): ReflectionVerdict {
  if (typeof value !== "string") {
    return "uncertain";
  }
  const v = value.trim().toLowerCase();
  if (["reaffirmed", "real", "confirmed", "true", "vulnerable"].includes(v)) {
    return "reaffirmed";
  }
  if (
    ["likely-false-positive", "false-positive", "false_positive", "false positive", "fp", "benign", "not-an-issue", "false"].includes(
      v
    )
  ) {
    return "likely-false-positive";
  }
  return "uncertain";
}

function normalizeReflection(raw: unknown): AiReflection | undefined {
  if (!raw || typeof raw !== "object") {
    return undefined;
  }
  const obj = raw as Record<string, unknown>;
  const findingId = ["findingId", "finding_id", "id"]
    .map((key) => obj[key])
    .find((value) => typeof value === "string");
  if (typeof findingId !== "string") {
    return undefined;
  }
  const reasoning =
    ["reasoning", "reason", "analysis", "detail"]
      .map((key) => obj[key])
      .find((value) => typeof value === "string") ?? "";
  return {
    findingId,
    verdict: normalizeVerdict(obj.verdict),
    reasoning: typeof reasoning === "string" ? reasoning : ""
  };
}

export function parseReflectionResponse(text: string): AgentResponse<{ reflections: AiReflection[] }> {
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
    const rawList = obj.reflections ?? obj.results ?? obj.verdicts ?? obj.items;
    const reflections = Array.isArray(rawList)
      ? rawList
          .map(normalizeReflection)
          .filter((entry): entry is AiReflection => entry !== undefined)
      : [];
    return { type: "final", result: { reflections } };
  }
  return undefined;
}

export const REFLECTION_FINAL_EXAMPLE =
  '{"type":"tool_call","tool":"<name>","args":{...}}  or  {"type":"final","reflections":[{"findingId":"...","verdict":"reaffirmed|likely-false-positive|uncertain","reasoning":"..."}]}';

export function buildReflectionSystemPrompt(config: AiProviderConfig): string {
  const toolGuidance =
    config.dataSharingMode === "metadata-only"
      ? "No tools are available. Base your verdicts only on the provided finding metadata."
      : "Read files and search code before concluding. Verify each finding against real code.";
  return [
    "You are an adversarial security re-reviewer. Your goal is to DISPROVE each finding: assume every finding is a false positive until evidence in the actual code proves otherwise.",
    "Only reaffirm a finding when you have verified concrete evidence in the source code.",
    toolGuidance,
    "Respond ONLY with a single JSON object: either a tool_call or a final result with the reflections schema."
  ].join("\n");
}

export function buildReflectionPrompt(findings: Finding[], report: AuditReport, config: AiProviderConfig): string {
  const langInstruction: Record<string, string> = {
    en: "You MUST respond in English.",
    "zh-TW": "你必須使用繁體中文回覆。",
    "zh-CN": "你必须使用简体中文回复。"
  };
  const lang = config.language ?? "zh-TW";
  const findingsJson = JSON.stringify(findings.map((finding) => serializeFindingForPrompt(finding, config)), null, 2);
  const readGuidance =
    config.dataSharingMode === "metadata-only"
      ? "Base your verdicts only on the provided finding metadata."
      : "Read the actual source code with the available tools to verify the evidence before concluding.";
  const prompt = [
    "You are re-reviewing high-risk security findings adversarially.",
    "For EACH finding, try hard to disprove it. Provide exactly one verdict per findingId.",
    readGuidance,
    'Verdicts: "reaffirmed" (verified real), "likely-false-positive" (disproven or unsupported), or "uncertain".',
    langInstruction[lang] ?? langInstruction["zh-TW"],
    "",
    "FINDINGS:",
    findingsJson
  ].join("\n");

  return config.redactionEnabled ? redactSecrets(prompt) : prompt;
}

export async function runReflection(
  findings: Finding[],
  report: AuditReport,
  config: AiProviderConfig,
  options: ReflectionOptions = {},
  fetchImpl?: FetchLike
): Promise<ReflectionRunResult> {
  const scanPath = options.scanPath ?? report.target.localPath ?? "";
  const mode: ReviewToolContext["mode"] = config.dataSharingMode === "full-files" ? "full-files" : "snippets";
  const ctx: ReviewToolContext = {
    scanPath,
    mode,
    allowedFiles:
      config.dataSharingMode === "finding-snippets"
        ? [...new Set(findings.map((finding) => finding.filePath))]
        : undefined
  };
  const tools = buildTools(config.dataSharingMode, ctx);

  try {
    const loopResult = await runAgentLoop(
      config,
      buildReflectionSystemPrompt(config),
      buildReflectionPrompt(findings, report, config),
      tools,
      ctx,
      {
        maxRounds: options.maxRounds ?? 6,
        maxTokensPerReview: options.maxTokensPerReview ?? 30_000,
        parseResponse: parseReflectionResponse,
        finalExample: REFLECTION_FINAL_EXAMPLE
      },
      fetchImpl
    );
    const validIds = new Set(findings.map((finding) => finding.id));
    const reflections = (loopResult.result?.reflections ?? []).filter((entry) => validIds.has(entry.findingId));
    return { reflections, raw: loopResult.raw, truncated: false };
  } catch {
    return { reflections: [], raw: "", truncated: true };
  }
}
