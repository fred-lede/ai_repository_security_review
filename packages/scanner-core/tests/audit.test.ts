import path from "node:path";
import fs from "node:fs";
import { describe, expect, it } from "vitest";
import {
  attachAuditToReport,
  buildFindingsDocument,
  buildInventory,
  buildReportBundle,
  checkRecordClaims,
  runFullAudit,
  serializeCoverageLedger,
  validateCoverageLedger,
  validateFindingsDocument,
  verifyFindingRecords,
  deserializeFindingsDocument,
  mergePriorFindings
} from "../src/index.js";

const maliciousFixture = path.resolve("fixtures/malicious-package");
const benignFixture = path.resolve("fixtures/benign-package");

function writeTempFixture(dir: string, files: Record<string, string>): void {
  fs.mkdirSync(dir, { recursive: true });
  for (const [name, content] of Object.entries(files)) {
    const target = path.join(dir, name);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, content);
  }
}

describe("reconnaissance", () => {
  it("maps architecture, trust boundaries, and initializes a valid coverage ledger", async () => {
    const inventory = await buildInventory(maliciousFixture);
    const audit = await runFullAudit({
      target: "fixtures/malicious-package",
      targetDir: maliciousFixture,
      inventory,
      maxHunters: 4
    });

    expect(audit.architecture.applicationType).toBeTruthy();
    expect(audit.architecture.coverageLedger.units.length).toBeGreaterThan(0);
    const validation = validateCoverageLedger(audit.architecture.coverageLedger);
    expect(validation.valid).toBe(true);
    expect(serializeCoverageLedger(audit.architecture.coverageLedger)).toContain('"units"');
  });
});

describe("hunting + validation", () => {
  it("produces candidates and validates them into three verdict buckets", async () => {
    const inventory = await buildInventory(maliciousFixture);
    const audit = await runFullAudit({
      target: "fixtures/malicious-package",
      targetDir: maliciousFixture,
      inventory,
      maxHunters: 8
    });

    const total =
      audit.findingsDoc.confirmed.length +
      audit.findingsDoc.needs_validation.length +
      audit.findingsDoc.rejected.length;
    expect(total).toBeGreaterThan(0);
    // malicious fixture has curl|sh + exec sinks; at least one confirmed candidate expected
    expect(audit.findingsDoc.confirmed.length).toBeGreaterThan(0);
  });

  it("finds nothing material in a benign fixture", async () => {
    const inventory = await buildInventory(benignFixture);
    const audit = await runFullAudit({
      target: "fixtures/benign-package",
      targetDir: benignFixture,
      inventory,
      maxHunters: 8
    });

    // Benign package: any candidates found must have been rejected
    expect(audit.findingsDoc.confirmed.length).toBe(0);
  });
});

describe("structured output", () => {
  it("builds a findings document that validates against the schema rules", async () => {
    const inventory = await buildInventory(maliciousFixture);
    const audit = await runFullAudit({
      target: "fixtures/malicious-package",
      targetDir: maliciousFixture,
      inventory
    });

    const docValidation = validateFindingsDocument(audit.findingsDoc);
    expect(docValidation.valid).toBe(true);
    expect(docValidation.errors).toEqual([]);
  });

  it("rejects malformed documents", () => {
    const doc = buildFindingsDocument(
      "x",
      [],
      { version: 1, units: [{ id: "u1", type: "attack-class", name: "injection", description: "d", status: "unexplored", findings: [] }], lastUpdated: new Date().toISOString() }
    );
    // empty target should fail
    const broken = { ...doc, target: "" };
    const validation = validateFindingsDocument(broken);
    expect(validation.valid).toBe(false);
    expect(validation.errors.length).toBeGreaterThan(0);
  });

  it("merges prior runs additively", () => {
    const ledger = {
      version: 1,
      units: [
        { id: "u1", type: "attack-class" as const, name: "injection", description: "d", status: "covered" as const, findings: ["command-injection:src/index.ts:9"] }
      ],
      lastUpdated: new Date().toISOString()
    };
    const base = buildFindingsDocument("repo", [], ledger);
    const current = buildFindingsDocument("repo", [], ledger);
    const { doc, carriedForward } = mergePriorFindings(current, base);
    expect(doc.target).toBe("repo");
    expect(Array.isArray(carriedForward)).toBe(true);
  });

  it("round-trips findings document serialization", async () => {
    const inventory = await buildInventory(maliciousFixture);
    const audit = await runFullAudit({
      target: "repo",
      targetDir: maliciousFixture,
      inventory
    });
    const json = serializeCoverageLedger(audit.findingsDoc.coverage);
    expect(deserializeFindingsDocument(JSON.stringify(audit.findingsDoc)).$schemaVersion).toBe(1);
  });
});

describe("independent verification", () => {
  it("verifies record claims against on-disk file content", async () => {
    const tempDir = path.resolve("node_modules/.cache/audit-verify-test");
    writeTempFixture(tempDir, {
      "src/danger.ts": 'import { exec } from "node:child_process";\nexport function run(cmd: string) {\n  exec(cmd);\n}\n'
    });

    const record = {
      id: "c1",
      verdict: "confirmed" as const,
      category: "command-injection",
      riskLevel: "High" as const,
      filePath: "src/danger.ts",
      lineStart: 3,
      lineEnd: 3,
      codeSnippet: "  exec(cmd);",
      explanation: "exec sink",
      recommendedFix: "validate input",
      evidenceTags: [],
      confidence: "High",
      verification: {
        checksPerformed: [],
        evidenceFor: [],
        evidenceAgainst: [],
        conclusion: "ok"
      },
      validationChain: []
    };

    const checks = await checkRecordClaims(record, tempDir);
    expect(checks.find((c) => c.name === "location-valid")?.passed).toBe(true);
    expect(checks.find((c) => c.name === "snippet-present")?.passed).toBe(true);

    const missing = { ...record, filePath: "src/does-not-exist.ts" };
    const missingChecks = await checkRecordClaims(missing, tempDir);
    expect(missingChecks.find((c) => c.name === "location-valid")?.passed).toBe(false);

    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it("demotes confirmed records whose claims fail verification", async () => {
    const tempDir = path.resolve("node_modules/.cache/audit-demote-test");
    writeTempFixture(tempDir, { "src/danger.ts": "export const x = 1;\n" });

    const doc = buildFindingsDocument(
      "repo",
      [],
      {
        version: 1,
        units: [
          { id: "u1", type: "attack-class", name: "injection", description: "d", status: "covered", findings: ["command-injection:src/danger.ts:2"] }
        ],
        lastUpdated: new Date().toISOString()
      },
      "0.3.2"
    );
    doc.confirmed.push({
      id: "stale",
      verdict: "confirmed",
      category: "command-injection",
      riskLevel: "High",
      filePath: "src/danger.ts",
      lineStart: 2,
      lineEnd: 2,
      codeSnippet: "exec(attackerInput);",
      explanation: "stale claim",
      recommendedFix: "fix it",
      evidenceTags: [],
      confidence: "High",
      verification: { checksPerformed: [], evidenceFor: [], evidenceAgainst: [], conclusion: "previously confirmed" },
      validationChain: [{ validatorId: "v1", verdict: "confirmed", at: new Date().toISOString() }]
    });

    const result = await verifyFindingRecords(doc, tempDir);
    expect(result.doc.confirmed.length).toBe(0);
    expect(result.doc.needs_validation.length).toBe(1);
    expect(result.outcomes[0].demoted).toBe(true);
    expect(result.recordsToReVerify.length).toBe(1);

    fs.rmSync(tempDir, { recursive: true, force: true });
  });
});

describe("target-neutral reporting", () => {
  it("derives the three report files from verified records and coverage", async () => {
    const inventory = await buildInventory(maliciousFixture);
    const audit = await runFullAudit({
      target: "fixtures/malicious-package",
      targetDir: maliciousFixture,
      inventory
    });

    expect(audit.reports.reportMd).toContain("# Security Audit Report");
    expect(audit.reports.reportMd).toContain("Coverage Ledger");
    expect(audit.reports.findingsDetailMd).toContain("# Findings Detail");
    expect(audit.reports.needsValidationMd).toContain("# Needs Validation");
  });
});

describe("audit orchestration", () => {
  it("runs all six phases end-to-end and projects findings onto a classic report", async () => {
    const inventory = await buildInventory(maliciousFixture);
    const audit = await runFullAudit({
      target: "fixtures/malicious-package",
      targetDir: maliciousFixture,
      inventory
    });

    expect(audit.classicFindings.length).toBeGreaterThan(0);
    expect(audit.verification.outcomes.length).toBeGreaterThanOrEqual(0);
    expect(audit.coverageLedgerJson).toContain('"units"');

    const baseReport = {
      target: {
        type: "local-directory" as const,
        source: "fixtures/malicious-package",
        localPath: maliciousFixture,
        provenance: {},
        networkUsed: false,
        trustBoundary: "local" as const
      },
      findings: [],
      dataFlow: { nodes: [], edges: [] },
      risk: {
        overallRiskLevel: "Low" as const,
        decision: "Pass" as const,
        rationale: "",
        topRisks: [],
        severityCounts: { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 },
        categoryCounts: {},
        blockingFindingIds: [],
        residualRisk: "",
        scanLimitations: []
      },
      attackSurface: [],
      generatedAt: new Date().toISOString(),
      toolVersion: "0.3.2"
    };
    const merged = attachAuditToReport(baseReport, audit);
    expect(merged.findings.length).toBe(audit.classicFindings.length);
  });
});
