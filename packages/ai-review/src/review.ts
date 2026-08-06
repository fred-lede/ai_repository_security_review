import { assessRisk, buildAttackSurface } from "@repo-auditor/scanner-core";
import type { AuditReport, Finding, Language } from "@repo-auditor/scanner-core";
import { runAgentLoop, type AgentLoopResult, type AgentNote } from "./agent.js";
import { buildProviderRequest, requestProviderCompletion, type FetchLike } from "./providers.js";
import { redactSecrets } from "./redaction.js";
import { buildTools, type ReviewToolContext } from "./tools.js";
import type { AiNewFinding, AiProviderConfig, AiReviewOptions, AiReviewResult } from "./types.js";

export function buildAiReviewPrompt(report: AuditReport, config: AiProviderConfig): string {
  const findings = report.findings.map((finding) => serializeFindingForPrompt(finding, config));
  const langInstruction: Record<string, string> = {
    en: "You MUST respond in English.",
    "zh-TW": "你必須使用繁體中文回覆。",
    "zh-CN": "你必须使用简体中文回复。"
  };
  const lang = config.language ?? "zh-TW";
  const prompt = [
    "You are reviewing deterministic security scanner findings.",
    "You MAY add new findings for phishing, network attack, or data exfiltration only, and only after verifying the evidence in real code.",
    "Do not invent findings in any other category.",
    "Mark uncertainty clearly and focus on risk, false-positive considerations, and safer patterns.",
    langInstruction[lang] ?? langInstruction["zh-TW"],
    JSON.stringify(
      {
        decision: report.risk.decision,
        overallRiskLevel: report.risk.overallRiskLevel,
        dataSharingMode: config.dataSharingMode,
        findings
      },
      null,
      2
    )
  ].join("\n\n");

  return config.redactionEnabled ? redactSecrets(prompt) : prompt;
}

const riskOrder: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

export async function runAiReview(
  report: AuditReport,
  config: AiProviderConfig,
  options: AiReviewOptions = {},
  fetchImpl?: FetchLike
): Promise<AiReviewResult> {
  const scanPath = options.scanPath ?? report.target.localPath ?? undefined;
  const maxRounds = options.maxRounds ?? 6;
  const maxFindingsPerBatch = options.maxFindingsPerBatch ?? 10;
  const maxTokensPerReview = options.maxTokensPerReview ?? 200_000;

  const mode: ReviewToolContext["mode"] = config.dataSharingMode === "full-files" ? "full-files" : "snippets";
  const ctx: ReviewToolContext = {
    scanPath: scanPath ?? "",
    mode,
    allowedFiles: config.dataSharingMode === "finding-snippets" ? uniqueFiles(report.findings) : undefined
  };
  const tools = buildTools(config.dataSharingMode, ctx);

  const batches = groupFindings(report.findings, maxFindingsPerBatch);
  if (batches.length === 0) {
    return createOfflineAiReviewPlaceholder(report, config);
  }

  const notes: AgentNote[] = [];
  const summaries: string[] = [];
  const rawTexts: string[] = [];
  const budgetPerBatch = Math.max(2000, Math.floor(maxTokensPerReview / batches.length));
  const newFindings: Finding[] = [];
  let truncated = false;
  const maxTotalMs = options.maxTotalMs ?? 600_000;
  const deadline = Date.now() + maxTotalMs;
  const controller = new AbortController();

  for (let index = 0; index < batches.length; index += 1) {
    const batch = batches[index];
    options.onBatchProgress?.(index, batches.length);

    if (Date.now() >= deadline || controller.signal.aborted) {
      truncated = true;
      break;
    }

    let loopResult: AgentLoopResult;
    try {
      loopResult = await runAgentLoop(
        config,
        buildSystemPrompt(config),
        buildBatchPrompt(report, batch, config, ctx),
        tools,
        ctx,
        { maxRounds, maxTokensPerReview: budgetPerBatch },
        fetchImpl
      );
    } catch {
      truncated = true;
      break;
    }

    if (loopResult.result) {
      summaries.push(loopResult.result.summary);
      notes.push(...loopResult.result.notes);
      newFindings.push(...normalizeAiFindings(loopResult.result.newFindings));
    } else if (loopResult.raw) {
      rawTexts.push(loopResult.raw);
    }
  }

  const fallback = createOfflineAiReviewPlaceholder(report, config);
  const summary =
    summaries.length > 0 ? summaries.join("\n\n") : rawTexts.filter(Boolean).join("\n\n") || fallback.summary;

  return {
    providerType: config.type,
    model: config.model,
    generatedAt: new Date().toISOString(),
    summary,
    findingNotes: notes.length > 0 ? mergeNotes(fallback.findingNotes, notes) : fallback.findingNotes,
    newFindings,
    truncated
  };
}

function uniqueFiles(findings: Finding[]): string[] {
  return Array.from(new Set(findings.map((finding) => finding.filePath)));
}

function groupFindings(findings: Finding[], maxPerBatch: number): Finding[][] {
  if (findings.length === 0) {
    return [];
  }

  const byCategory = new Map<string, Finding[]>();
  for (const finding of findings) {
    const list = byCategory.get(finding.category) ?? [];
    list.push(finding);
    byCategory.set(finding.category, list);
  }

  const ordered = Array.from(byCategory.entries()).sort(
    (a, b) => (riskOrder[a[1][0].riskLevel] ?? 99) - (riskOrder[b[1][0].riskLevel] ?? 99)
  );

  const batches: Finding[][] = [];
  for (const [, list] of ordered) {
    for (let i = 0; i < list.length; i += maxPerBatch) {
      batches.push(list.slice(i, i + maxPerBatch));
    }
  }
  return batches;
}

function mergeNotes(
  fallback: AiReviewResult["findingNotes"],
  agentNotes: AgentNote[]
): AiReviewResult["findingNotes"] {
  const agentById = new Map(agentNotes.map((note) => [note.findingId, note]));
  return fallback.map((note) => {
    const agent = agentById.get(note.findingId);
    if (!agent) {
      return note;
    }
    return {
      findingId: note.findingId,
      explanation: agent.explanation,
      falsePositiveNote: agent.falsePositiveNote,
      saferPattern: agent.saferPattern ?? note.saferPattern
    };
  });
}

const allowedAiCategories = new Set(["phishing", "network-attack", "data-exfiltration"]);

export function normalizeAiFindings(newFindings: AiNewFinding[]): Finding[] {
  const out: Finding[] = [];

  for (const nf of newFindings) {
    if (!nf || !allowedAiCategories.has(nf.category)) {
      continue;
    }
    if (!nf.filePath || !nf.codeSnippet) {
      continue;
    }
    const lineStart = Number(nf.lineStart);
    const lineEnd = Number(nf.lineEnd);
    if (!Number.isFinite(lineStart) || !Number.isFinite(lineEnd)) {
      continue;
    }

    out.push({
      id: "",
      riskLevel: "Medium",
      category: nf.category as Finding["category"],
      filePath: nf.filePath,
      lineStart,
      lineEnd: Math.max(lineStart, lineEnd),
      codeSnippet: nf.codeSnippet,
      explanation: nf.explanation,
      recommendedFix: nf.recommendedFix,
      evidenceTags: ["ai-sourced", nf.category],
      source: "ai",
      confidence: "Low"
    });
  }

  return out;
}

export function mergeAiFindingsIntoReport(report: AuditReport, result: AiReviewResult): AuditReport {
  const findings = [...report.findings, ...result.newFindings];
  const risk = assessRisk(findings, (report as { language?: Language }).language ?? "zh-TW");
  return {
    ...report,
    findings,
    risk,
    attackSurface: buildAttackSurface({ ...report, findings })
  };
}

function buildSystemPrompt(config: AiProviderConfig): string {
  const toolGuidance =
    config.dataSharingMode === "metadata-only"
      ? "No tools are available. Respond with a final JSON object based only on the metadata provided."
      : "Read files and search code before concluding. Verify each finding against real code.";
  return [
    "You are a security audit review agent.",
    toolGuidance,
    "Respond ONLY with a single JSON object matching the requested schema."
  ].join("\n");
}

function buildBatchPrompt(
  report: AuditReport,
  batch: Finding[],
  config: AiProviderConfig,
  ctx: ReviewToolContext
): string {
  const langInstruction: Record<string, string> = {
    en: "You MUST respond in English.",
    "zh-TW": "你必須使用繁體中文回覆。",
    "zh-CN": "你必须使用简体中文回复。"
  };
  const lang = config.language ?? "zh-TW";
  const findingsJson = JSON.stringify(batch.map((finding) => serializeFindingForPrompt(finding, config)), null, 2);
  const fileHint =
    ctx.allowedFiles && ctx.allowedFiles.length > 0
      ? `\nFiles you may read: ${ctx.allowedFiles.join(", ")}`
      : "";

  const prompt = [
    "You are investigating deterministic security scanner findings.",
    "You MAY add new findings for phishing, network attack, or data exfiltration, but only after reading the real source with file_read or code_search to verify the evidence.",
    "Do not invent findings in any other category.",
    "Use tools to read the actual source code and verify each finding before writing notes.",
    "For each finding decide: real risk, likelihood of a false positive, and a safer pattern.",
    `There are ${batch.length} finding(s) to review in this batch.`,
    langInstruction[lang] ?? langInstruction["zh-TW"],
    "",
    "FINDINGS:",
    findingsJson,
    fileHint
  ].join("\n");

  return config.redactionEnabled ? redactSecrets(prompt) : prompt;
}

export function createOfflineAiReviewPlaceholder(report: AuditReport, config: AiProviderConfig): AiReviewResult {
  const t = findingNotesTranslator(config.language ?? "zh-TW");
  return {
    providerType: config.type,
    model: config.model,
    generatedAt: new Date().toISOString(),
    summary: `AI review configured for ${config.type}. Provider execution is optional and separate from deterministic scanning.`,
    findingNotes: report.findings.map((finding) => ({
      findingId: finding.id,
      explanation: t("reviewEvidence", finding.category, finding.filePath),
      saferPattern: t(finding.recommendedFix)
    })),
    newFindings: [],
    truncated: false
  };
}

export function previewProviderRequest(report: AuditReport, config: AiProviderConfig) {
  return buildProviderRequest(config, buildAiReviewPrompt(report, config));
}

function findingNotesTranslator(lang: string) {
  const dict: Record<string, Record<string, string>> = {
    en: {
      reviewEvidence: "Review evidence for {category} at {filePath}.",
      "Remove install-time side effects or move setup behind an explicit user command.":
        "Remove install-time side effects or move setup behind an explicit user command.",
      "Replace with a pinned registry version and verify the lockfile integrity.":
        "Replace with a pinned registry version and verify the lockfile integrity.",
      "Avoid shell execution. Use safe APIs with explicit argument arrays and strict input validation.":
        "Avoid shell execution. Use safe APIs with explicit argument arrays and strict input validation.",
      "Keep test/example endpoints out of production configuration and ensure they cannot be selected at runtime.":
        "Keep test/example endpoints out of production configuration and ensure they cannot be selected at runtime.",
      "Document expected endpoints, minimize payloads, and require explicit consent before sending sensitive data.":
        "Document expected endpoints, minimize payloads, and require explicit consent before sending sensitive data."
    },
    "zh-TW": {
      reviewEvidence: "在 {filePath} 檢查 {category} 的證據。",
      "Remove install-time side effects or move setup behind an explicit user command.":
        "移除安裝時期的副作用，或將設定移至明確的使用者指令之後。",
      "Replace with a pinned registry version and verify the lockfile integrity.":
        "取代為固定的 registry 版本，並驗證 lockfile 完整性。",
      "Avoid shell execution. Use safe APIs with explicit argument arrays and strict input validation.":
        "避免使用 shell 執行。使用安全的 API 搭配明確的參數陣列與嚴格的輸入驗證。",
      "Keep test/example endpoints out of production configuration and ensure they cannot be selected at runtime.":
        "將測試／範例端點移出正式環境設定，並確保它們無法在執行時期被選用。",
      "Document expected endpoints, minimize payloads, and require explicit consent before sending sensitive data.":
        "記錄預期的端點、最小化酬載，並在傳送敏感資料前要求明確同意。"
    },
    "zh-CN": {
      reviewEvidence: "在 {filePath} 检查 {category} 的证据。",
      "Remove install-time side effects or move setup behind an explicit user command.":
        "移除安装时的副作用，或将设置移至明确的用户命令之后。",
      "Replace with a pinned registry version and verify the lockfile integrity.":
        "替换为固定的 registry 版本，并验证 lockfile 完整性。",
      "Avoid shell execution. Use safe APIs with explicit argument arrays and strict input validation.":
        "避免使用 shell 执行。使用安全的 API 搭配明确的参数数组与严格的输入验证。",
      "Keep test/example endpoints out of production configuration and ensure they cannot be selected at runtime.":
        "将测试/示例端点移出生产环境配置，并确保它们无法在运行时被选用。",
      "Document expected endpoints, minimize payloads, and require explicit consent before sending sensitive data.":
        "记录预期的端点、最小化负载，并在发送敏感数据前要求明确同意。"
    }
  };
  const t = dict[lang] ?? dict.en;
  return (key: string, ...args: string[]) => {
    let msg = t[key] ?? key;
    if (args.length >= 2) {
      msg = msg.replace("{category}", args[0]).replace("{filePath}", args[1]);
    }
    return msg;
  };
}

export function serializeFindingForPrompt(finding: Finding, config: AiProviderConfig) {
  return {
    id: finding.id,
    riskLevel: finding.riskLevel,
    category: finding.category,
    filePath: finding.filePath,
    lineStart: finding.lineStart,
    lineEnd: finding.lineEnd,
    explanation: finding.explanation,
    recommendedFix: finding.recommendedFix,
    evidenceTags: finding.evidenceTags,
    codeSnippet: config.dataSharingMode === "metadata-only" ? undefined : finding.codeSnippet
  };
}
