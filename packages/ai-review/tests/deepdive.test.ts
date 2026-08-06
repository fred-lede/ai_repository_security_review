import { describe, expect, it } from "vitest";
import { buildDeepDivePrompt, buildDeepDiveSystemPrompt, parseDeepDiveResponse } from "../src/deepdive.js";
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
    expect(pick(JSON.stringify({ type: "final", verdict: "false_positive" }))).toBe("false-positive");
    expect(pick(JSON.stringify({ type: "final", verdict: "false positive" }))).toBe("false-positive");
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

  it("falls through to a valid alias when the primary fixSteps key is invalid", () => {
    const parsed = parseDeepDiveResponse(
      JSON.stringify({ type: "final", verdict: "real", fixSteps: 3, recommendations: ["good step"] })
    );
    if (parsed?.type === "final") {
      expect(parsed.result.fixSteps).toEqual(["good step"]);
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

  it("does not instruct reading source code in metadata-only mode", () => {
    const prompt = buildDeepDivePrompt(finding, report, { ...config, dataSharingMode: "metadata-only" });
    expect(prompt).not.toContain("available tools");
  });

  it("instructs reading source code when tools are available", () => {
    const prompt = buildDeepDivePrompt(finding, report, { ...config, dataSharingMode: "full-files" });
    expect(prompt).toContain("Read the actual source code with the available tools");
  });
});

describe("buildDeepDiveSystemPrompt", () => {
  it("disables tools in metadata-only mode", () => {
    const prompt = buildDeepDiveSystemPrompt({ ...config, dataSharingMode: "metadata-only" });
    expect(prompt).toContain("No tools are available");
  });

  it("instructs reading and searching code when tools are available", () => {
    const prompt = buildDeepDiveSystemPrompt({ ...config, dataSharingMode: "full-files" });
    expect(prompt).toContain("Read files and search code");
  });
});
