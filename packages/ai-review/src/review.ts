import type { AuditReport, Finding } from "@repo-auditor/scanner-core";
import { buildProviderRequest, requestProviderCompletion, type FetchLike } from "./providers.js";
import { redactSecrets } from "./redaction.js";
import type { AiProviderConfig, AiReviewResult } from "./types.js";

export function buildAiReviewPrompt(report: AuditReport, config: AiProviderConfig): string {
  const findings = report.findings.map((finding) => serializeFindingForPrompt(finding, config));
  const prompt = [
    "You are reviewing deterministic security scanner findings.",
    "Do not create new findings. Explain only the evidence provided.",
    "Mark uncertainty clearly and focus on risk, false-positive considerations, and safer patterns.",
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
  return {
    providerType: config.type,
    model: config.model,
    generatedAt: new Date().toISOString(),
    summary: `AI review configured for ${config.type}. Provider execution is optional and separate from deterministic scanning.`,
    findingNotes: report.findings.map((finding) => ({
      findingId: finding.id,
      explanation: `Review evidence for ${finding.category} at ${finding.filePath}.`,
      saferPattern: finding.recommendedFix
    }))
  };
}

export function previewProviderRequest(report: AuditReport, config: AiProviderConfig) {
  return buildProviderRequest(config, buildAiReviewPrompt(report, config));
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
