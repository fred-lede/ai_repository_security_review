import type { AuditReport, Finding } from "@repo-auditor/scanner-core";
import { buildProviderRequest, requestProviderCompletion, type FetchLike } from "./providers.js";
import { redactSecrets } from "./redaction.js";
import type { AiProviderConfig, AiReviewResult } from "./types.js";

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
    "Do not create new findings. Explain only the evidence provided.",
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

export async function runAiReview(
  report: AuditReport,
  config: AiProviderConfig,
  fetchImpl?: FetchLike
): Promise<AiReviewResult> {
  const prompt = buildAiReviewPrompt(report, config);
  const completion = await requestProviderCompletion(config, prompt, fetchImpl);

  return {
    ...createOfflineAiReviewPlaceholder(report, config),
    summary: completion
  };
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
    }))
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

function serializeFindingForPrompt(finding: Finding, config: AiProviderConfig) {
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
