# Report Enhancement (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Trust Score (0-100), Risk Matrix, Attack Surface Summary, and standalone HTML report to the scanner output.

**Architecture:** All new code derives from existing `AuditReport` and `ProjectInventory` types. No scan logic changes. Trust score computed at scan time alongside risk assessment. Attack surface derived from inventory at scan time. HTML report is a pure string renderer like existing markdown/mermaid/sarif reporters.

**Tech Stack:** TypeScript, ESM, Vitest for tests, Electron's printToPDF for future PDF.

---

### Task 1: Add types (OutputFormat, AttackSurfaceEntry, AuditReport.attackSurface)

**Files:**
- Modify: `packages/scanner-core/src/types.ts`

- [ ] **Step 1: Add `html` to OutputFormat and add AttackSurfaceEntry interface**

Edit `packages/scanner-core/src/types.ts`:

```typescript
export type OutputFormat = "markdown" | "json" | "sarif" | "mermaid" | "html";

export interface AttackSurfaceEntry {
  category: string;
  count: number;
  highlights: string[];
}
```

- [ ] **Step 2: Add `attackSurface` to AuditReport**

Edit `packages/scanner-core/src/types.ts`, add to AuditReport:

```typescript
export interface AuditReport {
  target: ResolvedTarget;
  findings: Finding[];
  dataFlow: DataFlowGraph;
  risk: RiskAssessment;
  attackSurface: AttackSurfaceEntry[];
  generatedAt: string;
  toolVersion: string;
}
```

- [ ] **Step 3: Build and run tests to confirm no breakage**

Run: `npm run build --workspace @repo-auditor/scanner-core && npm test`
Expected: Build succeeds, 79 tests pass (some may fail due to missing `attackSurface` in test fixtures — we'll fix those in Task 7)

- [ ] **Step 4: Commit**

```bash
git add packages/scanner-core/src/types.ts
git commit -m "feat: add html OutputFormat, AttackSurfaceEntry, attackSurface to AuditReport"
```

---

### Task 2: Add i18n keys for trust score, verdict, matrix, surface

**Files:**
- Modify: `packages/scanner-core/src/i18n.ts`

- [ ] **Step 1: Add trust score keys and verdict keys to i18n.ts**

Add to the `Translator` dictionary sections. Inside the existing `createTranslator` function, add these entries to the three language blocks (en, zh-TW, zh-CN):

```typescript
// Inside the en block:
"trustScore": "Trust Score",
"trustScoreLabel": "Trusted",
"trustScoreCaution": "Use With Caution",
"trustScoreHighRisk": "High Risk",
"trustScoreCritical": "Critical Risk",
"trustScoreGenerallySafe": "Generally Safe",
"verdictApproved": "APPROVED",
"verdictApprovedCaution": "APPROVED WITH CAUTION",
"verdictManualReview": "MANUAL REVIEW REQUIRED",
"verdictBlock": "BLOCK IMMEDIATELY",
"finalVerdict": "Final Verdict",

// Inside the zh-TW block:
"trustScore": "信任評分",
"trustScoreLabel": "可信",
"trustScoreCaution": "謹慎使用",
"trustScoreHighRisk": "高風險",
"trustScoreCritical": "嚴重風險",
"trustScoreGenerallySafe": "大致安全",
"verdictApproved": "已核准",
"verdictApprovedCaution": "有條件核准",
"verdictManualReview": "需要人工審查",
"verdictBlock": "立即封鎖",
"finalVerdict": "最終裁定",

// Inside the zh-CN block:
"trustScore": "信任评分",
"trustScoreLabel": "可信",
"trustScoreCaution": "谨慎使用",
"trustScoreHighRisk": "高风险",
"trustScoreCritical": "严重风险",
"trustScoreGenerallySafe": "大致安全",
"verdictApproved": "已核准",
"verdictApprovedCaution": "有条件核准",
"verdictManualReview": "需要人工审查",
"verdictBlock": "立即封锁",
"finalVerdict": "最终裁定",
```

- [ ] **Step 2: Add risk matrix and attack surface header keys**

Add to each language block:

```typescript
// en:
"riskMatrix": "Risk Matrix",
"attackSurface": "Attack Surface Summary",
"total": "Total",

// zh-TW:
"riskMatrix": "風險矩陣",
"attackSurface": "攻擊面摘要",
"total": "總計",

// zh-CN:
"riskMatrix": "风险矩阵",
"attackSurface": "攻击面摘要",
"total": "总计",
```

- [ ] **Step 3: Build and run tests**

Run: `npm run build --workspace @repo-auditor/scanner-core`
Expected: Build succeeds

- [ ] **Step 4: Commit**

```bash
git add packages/scanner-core/src/i18n.ts
git commit -m "feat: add i18n keys for trust score, verdict, matrix, surface"
```

---

### Task 3: Implement trust score and final verdict

**Files:**
- Create: `packages/scanner-core/src/trustScore.ts`
- Test: `packages/scanner-core/tests/trustScore.test.ts`

- [ ] **Step 1: Write failing tests**

Create `packages/scanner-core/tests/trustScore.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import { computeTrustScore, computeFinalVerdict } from "../src/trustScore.js";
import type { AuditReport, Finding, DataFlowEdge } from "../src/types.js";

function makeReport(overrides: Partial<AuditReport>): AuditReport {
  return {
    target: { type: "local-directory", source: "test", localPath: "test", provenance: {}, networkUsed: false, trustBoundary: "local" },
    findings: [],
    dataFlow: { nodes: [], edges: [] },
    risk: { overallRiskLevel: "Low", decision: "Pass", rationale: "", topRisks: [], severityCounts: { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 }, categoryCounts: {}, blockingFindingIds: [], residualRisk: "", scanLimitations: [] },
    generatedAt: "",
    toolVersion: "0.1.0",
    attackSurface: [],
    ...overrides
  };
}

describe("computeTrustScore", () => {
  it("returns 100 for a clean report", () => {
    expect(computeTrustScore(makeReport({}))).toBe(100);
  });

  it("deducts 25 per Critical finding", () => {
    const report = makeReport({
      findings: [
        { riskLevel: "Critical", category: "command-injection", id: "f1" } as Finding,
        { riskLevel: "Critical", category: "command-injection", id: "f2" } as Finding
      ]
    });
    expect(computeTrustScore(report)).toBe(50);
  });

  it("deducts 12 per High finding", () => {
    const report = makeReport({
      findings: [
        { riskLevel: "High", category: "network", id: "f1" } as Finding
      ]
    });
    expect(computeTrustScore(report)).toBe(88);
  });

  it("deducts 5 per Medium, 1 per Low", () => {
    const report = makeReport({
      findings: [
        { riskLevel: "Medium", category: "network", id: "f1" } as Finding,
        { riskLevel: "Low", category: "network", id: "f2" } as Finding
      ]
    });
    expect(computeTrustScore(report)).toBe(94); // 100 - 5 - 1
  });

  it("deducts 10 for Block decision", () => {
    const report = makeReport({
      risk: { overallRiskLevel: "High", decision: "Block", rationale: "", topRisks: [], severityCounts: { Critical: 0, High: 1, Medium: 0, Low: 0, Info: 0 }, categoryCounts: {}, blockingFindingIds: ["f1"], residualRisk: "", scanLimitations: [] }
    });
    expect(computeTrustScore(report)).toBe(90);
  });

  it("deducts 10 for exfiltration edge", () => {
    const report = makeReport({
      dataFlow: {
        nodes: [],
        edges: [{ id: "e1", from: "n1", to: "n2", label: "credentials", findingIds: [] }]
      }
    });
    expect(computeTrustScore(report)).toBe(90);
  });

  it("clamps to 0 minimum", () => {
    const report = makeReport({
      findings: [
        { riskLevel: "Critical", category: "command-injection", id: "f1" } as Finding,
        { riskLevel: "Critical", category: "command-injection", id: "f2" } as Finding,
        { riskLevel: "Critical", category: "command-injection", id: "f3" } as Finding,
        { riskLevel: "Critical", category: "command-injection", id: "f4" } as Finding,
        { riskLevel: "Critical", category: "command-injection", id: "f5" } as Finding
      ]
    });
    expect(computeTrustScore(report)).toBe(0);
  });
});

describe("computeFinalVerdict", () => {
  it("returns BLOCK IMMEDIATELY for Block decision", () => {
    expect(computeFinalVerdict("Block", 50)).toBe("BLOCK IMMEDIATELY");
  });

  it("returns MANUAL REVIEW REQUIRED for Needs Review", () => {
    expect(computeFinalVerdict("Needs Review", 80)).toBe("MANUAL REVIEW REQUIRED");
  });

  it("returns MANUAL REVIEW REQUIRED for Monitor", () => {
    expect(computeFinalVerdict("Monitor", 80)).toBe("MANUAL REVIEW REQUIRED");
  });

  it("returns APPROVED for Pass with score >= 75", () => {
    expect(computeFinalVerdict("Pass", 90)).toBe("APPROVED");
  });

  it("returns APPROVED WITH CAUTION for Pass with score < 75", () => {
    expect(computeFinalVerdict("Pass", 60)).toBe("APPROVED WITH CAUTION");
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npm --workspace @repo-auditor/scanner-core test`
Expected: FAIL — `computeTrustScore` / `computeFinalVerdict` not found

- [ ] **Step 3: Implement trustScore.ts**

Create `packages/scanner-core/src/trustScore.ts`:

```typescript
import type { AuditReport, Decision } from "./types.js";

export function computeTrustScore(report: AuditReport): number {
  let score = 100;

  for (const finding of report.findings) {
    switch (finding.riskLevel) {
      case "Critical": score -= 25; break;
      case "High": score -= 12; break;
      case "Medium": score -= 5; break;
      case "Low": score -= 1; break;
    }
  }

  if (report.risk.decision === "Block") score -= 10;

  for (const edge of report.dataFlow.edges) {
    if (edge.label === "credentials" || edge.label === "sensitive") {
      score -= 10;
      break;
    }
  }

  return Math.max(0, Math.min(100, score));
}

export function computeFinalVerdict(decision: Decision, trustScore: number): string {
  if (decision === "Block") return "BLOCK IMMEDIATELY";
  if (decision === "Needs Review" || decision === "Monitor") return "MANUAL REVIEW REQUIRED";
  if (decision === "Pass") return trustScore >= 75 ? "APPROVED" : "APPROVED WITH CAUTION";
  return "MANUAL REVIEW REQUIRED";
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npm --workspace @repo-auditor/scanner-core test`
Expected: All trustScore tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/scanner-core/src/trustScore.ts packages/scanner-core/tests/trustScore.test.ts
git commit -m "feat: add trust score (0-100) and final verdict computation"
```

---

### Task 4: Implement buildRiskMatrix and buildAttackSurface

**Files:**
- Modify: `packages/scanner-core/src/reporters.ts`
- Modify: `packages/scanner-core/tests/reporters.test.ts`

- [ ] **Step 1: Write failing tests**

Add to `packages/scanner-core/tests/reporters.test.ts`:

```typescript
import { buildRiskMatrix, buildAttackSurface } from "../src/reporters.js";
import type { AttackSurfaceEntry } from "../src/types.js";

describe("buildRiskMatrix", () => {
  it("builds a category × riskLevel pivot from findings", () => {
    const findings = [
      { riskLevel: "Critical", category: "command-injection" } as any,
      { riskLevel: "High", category: "network" } as any,
      { riskLevel: "High", category: "network" } as any,
      { riskLevel: "Medium", category: "supply-chain" } as any
    ];
    const matrix = buildRiskMatrix(findings);
    expect(matrix["command-injection"]?.["Critical"]).toBe(1);
    expect(matrix["network"]?.["High"]).toBe(2);
    expect(matrix["supply-chain"]?.["Medium"]).toBe(1);
  });

  it("returns empty object for no findings", () => {
    expect(buildRiskMatrix([])).toEqual({});
  });
});

describe("buildAttackSurface", () => {
  it("returns array with all surface categories", () => {
    const inventory = {
      networkEndpoints: [{ endpoint: "https://evil.example", filePath: "src/index.ts", line: 1, snippet: "" }],
      commandExecutions: [{ filePath: "src/index.ts", line: 2, snippet: "" }],
      filesystemReads: [],
      environmentVariables: ["TELEGRAM_BOT_TOKEN"],
      persistenceIndicators: [],
      githubWorkflowFiles: [],
      electronIpcFiles: []
    } as any;
    const surface = buildAttackSurface(inventory);
    const net = surface.find(s => s.category === "network");
    expect(net?.count).toBe(1);
    expect(net?.highlights).toContain("https://evil.example");
    const env = surface.find(s => s.category === "env-vars");
    expect(env?.count).toBe(1);
    const cmd = surface.find(s => s.category === "command-exec");
    expect(cmd?.count).toBe(1);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npm --workspace @repo-auditor/scanner-core test`
Expected: FAIL — buildRiskMatrix / buildAttackSurface not found

- [ ] **Step 3: Implement buildRiskMatrix and buildAttackSurface**

Add to `packages/scanner-core/src/reporters.ts`:

```typescript
import type { AttackSurfaceEntry, AuditReport, Finding } from "./types.js";
import type { ProjectInventory } from "./inventory.js";

export function buildRiskMatrix(findings: Finding[]): Record<string, Record<string, number>> {
  const matrix: Record<string, Record<string, number>> = {};
  for (const f of findings) {
    if (!matrix[f.category]) matrix[f.category] = {};
    matrix[f.category][f.riskLevel] = (matrix[f.category][f.riskLevel] ?? 0) + 1;
  }
  return matrix;
}

export function buildAttackSurface(inventory: ProjectInventory): AttackSurfaceEntry[] {
  const entries: AttackSurfaceEntry[] = [];
  const netHighlights = inventory.networkEndpoints.map(e => e.endpoint).slice(0, 3);
  if (inventory.networkEndpoints.length > 0) entries.push({ category: "network", count: inventory.networkEndpoints.length, highlights: netHighlights });
  const cmdHighlights = inventory.commandExecutions.map(e => e.filePath).slice(0, 3);
  if (inventory.commandExecutions.length > 0) entries.push({ category: "command-exec", count: inventory.commandExecutions.length, highlights: cmdHighlights });
  if (inventory.filesystemReads.length > 0) entries.push({ category: "filesystem", count: inventory.filesystemReads.length, highlights: inventory.filesystemReads.map(e => e.filePath).slice(0, 3) });
  if (inventory.environmentVariables.length > 0) entries.push({ category: "env-vars", count: inventory.environmentVariables.length, highlights: inventory.environmentVariables.slice(0, 3) });
  if (inventory.persistenceIndicators.length > 0) entries.push({ category: "persistence", count: inventory.persistenceIndicators.length, highlights: inventory.persistenceIndicators.map(e => e.filePath).slice(0, 3) });
  if (inventory.githubWorkflowFiles.length > 0) entries.push({ category: "github-actions", count: inventory.githubWorkflowFiles.length, highlights: inventory.githubWorkflowFiles.slice(0, 3) });
  if (inventory.electronIpcFiles.length > 0) entries.push({ category: "electron-ipc", count: inventory.electronIpcFiles.length, highlights: inventory.electronIpcFiles.slice(0, 3) });
  return entries;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npm --workspace @repo-auditor/scanner-core test`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/scanner-core/src/reporters.ts packages/scanner-core/tests/reporters.test.ts
git commit -m "feat: add buildRiskMatrix and buildAttackSurface"
```

---

### Task 5: Implement renderHtmlReport

**Files:**
- Modify: `packages/scanner-core/src/reporters.ts`
- Modify: `packages/scanner-core/src/index.ts`

- [ ] **Step 1: Write failing test for HTML render**

Add to `packages/scanner-core/tests/reporters.test.ts`:

```typescript
import { renderHtmlReport } from "../src/reporters.js";

describe("renderHtmlReport", () => {
  it("produces a complete HTML document", () => {
    const report = {
      target: { type: "local-directory", source: "fixtures/malicious-package", localPath: "test", provenance: {}, networkUsed: false, trustBoundary: "local" },
      findings: [{
        id: "f1", riskLevel: "High", category: "network", filePath: "src/index.ts", lineStart: 1, lineEnd: 1,
        codeSnippet: 'fetch("https://evil.example")', explanation: "Suspicious network call", recommendedFix: "Verify",
        evidenceTags: ["network"], confidence: "High"
      }],
      dataFlow: { nodes: [{ id: "n1", label: "env", kind: "source", leavesMachine: false }], edges: [] },
      risk: { overallRiskLevel: "High", decision: "Block", rationale: "test", topRisks: ["High: network"], severityCounts: { Critical: 0, High: 1, Medium: 0, Low: 0, Info: 0 }, categoryCounts: { network: 1 }, blockingFindingIds: ["f1"], residualRisk: "", scanLimitations: [] },
      generatedAt: "2026-06-15T00:00:00.000Z",
      toolVersion: "0.1.0",
      attackSurface: [{ category: "network", count: 1, highlights: ["https://evil.example"] }]
    };
    const html = renderHtmlReport(report, 60, buildRiskMatrix(report.findings), "en");
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("Repository Security Audit Report");
    expect(html).toContain("Trust Score");
    expect(html).toContain("60");
    expect(html).toContain("BLOCK IMMEDIATELY");
    expect(html).toContain("Risk Matrix");
    expect(html).toContain("Attack Surface");
    expect(html).toContain("fixtures/malicious-package");
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npm --workspace @repo-auditor/scanner-core test`
Expected: FAIL — renderHtmlReport not found

- [ ] **Step 3: Implement renderHtmlReport**

Add to `packages/scanner-core/src/reporters.ts`:

```typescript
export function renderHtmlReport(
  report: AuditReport,
  trustScore: number,
  riskMatrix: Record<string, Record<string, number>>,
  lang: Language = "zh-TW"
): string {
  const t = createTranslator(lang);

  const riskLevels = ["Critical", "High", "Medium", "Low"];

  let matrixRows = "";
  for (const [category, counts] of Object.entries(riskMatrix).sort()) {
    const catLabel = t.formatCategory(category as any);
    const cells = riskLevels.map(rl => counts[rl] ?? 0).join("</td><td>");
    matrixRows += `<tr><td>${catLabel}</td><td>${cells}</td></tr>\n`;
  }

  let surfaceRows = "";
  for (const entry of report.attackSurface) {
    const highlights = entry.highlights.length > 0 ? entry.highlights.join(", ") : "—";
    surfaceRows += `<tr><td>${t.t("attackSurface")} - ${entry.category}</td><td>${entry.count}</td><td>${highlights}</td></tr>\n`;
  }

  let findingsHtml = "";
  for (const f of report.findings) {
    const color = f.riskLevel === "Critical" || f.riskLevel === "High" ? "#d1242f" : f.riskLevel === "Medium" ? "#bf8700" : f.riskLevel === "Low" ? "#1a7f37" : "#667586";
    findingsHtml += `<div class="finding" style="border-left:4px solid ${color}">
      <div class="finding-header"><span class="risk-badge" style="background:${color}">${t.formatRiskLevel(f.riskLevel)}</span> ${t.formatCategory(f.category)}</div>
      <div class="finding-location">${f.filePath}:${f.lineStart}</div>
      <pre class="snippet"><code>${escapeHtml(f.codeSnippet)}</code></pre>
      <p>${escapeHtml(f.explanation)}</p>
      <p><strong>${t.t("report.recommendedFix")}:</strong> ${escapeHtml(f.recommendedFix)}</p>
    </div>\n`;
  }

  let dataFlowHtml = "<ul>\n";
  for (const node of report.dataFlow.nodes) {
    dataFlowHtml += `  <li><strong>${escapeHtml(node.label)}</strong> (${node.kind})${node.leavesMachine ? " — leaves machine" : ""}</li>\n`;
  }
  dataFlowHtml += "</ul>\n";
  dataFlowHtml += "<pre><code>```mermaid\n" + renderMermaidDataFlow(report.dataFlow) + "\n```</code></pre>\n";

  const trustLabel = trustScore >= 90 ? t.t("trustScoreLabel") : trustScore >= 75 ? t.t("trustScoreGenerallySafe") : trustScore >= 50 ? t.t("trustScoreCaution") : trustScore >= 25 ? t.t("trustScoreHighRisk") : t.t("trustScoreCritical");
  const verdict = computeFinalVerdict(report.risk.decision, trustScore);
  const verdictKey = verdict === "APPROVED" ? "verdictApproved" : verdict === "APPROVED WITH CAUTION" ? "verdictApprovedCaution" : verdict === "MANUAL REVIEW REQUIRED" ? "verdictManualReview" : "verdictBlock";

  return `<!DOCTYPE html>
<html lang="${lang}">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Repository Security Audit — ${escapeHtml(report.target.source)}</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;margin:0;padding:22px;background:#f6f7f9;color:#17202a;line-height:1.5}
  h1{font-size:24px;margin:0 0 4px} h2{font-size:16px;margin:24px 0 8px;color:#526070;text-transform:uppercase}
  .meta{color:#667586;font-size:13px;margin-bottom:16px}
  .score{font-size:36px;font-weight:700;margin:8px 0}
  .score-label{font-size:14px;color:#667586}
  .verdict{font-size:20px;font-weight:700;margin:8px 0}
  table{width:100%;border-collapse:collapse;margin:8px 0 16px;font-size:13px}
  th,td{text-align:left;padding:6px 10px;border:1px solid #d9dee7}
  th{background:#eef0f4;font-weight:600}
  .finding{padding:12px 14px;margin:8px 0;background:#fff;border-radius:6px}
  .finding-header{font-weight:600;margin-bottom:4px}
  .risk-badge{display:inline-block;color:#fff;padding:1px 8px;border-radius:3px;font-size:12px;font-weight:600}
  .finding-location{font-size:12px;color:#667586;margin-bottom:6px}
  pre.snippet{background:#f0f2f5;padding:8px 10px;border-radius:4px;overflow-x:auto;font-size:12px}
  code{font-family:"SF Mono",Menlo,Consolas,monospace;font-size:12px}
  .footer{color:#667586;font-size:12px;margin-top:24px;border-top:1px solid #d9dee7;padding-top:12px}
</style>
</head>
<body>
<h1>🛡 ${t.t("report.title")}</h1>
<div class="meta">${escapeHtml(report.target.source)} · ${report.target.type} · ${report.generatedAt}</div>
<div class="score">${trustScore}/100</div>
<div class="score-label">${t.t("trustScore")}: ${trustLabel}</div>
<div class="verdict" style="color:${verdict === "BLOCK IMMEDIATELY" ? "#d1242f" : "#1a7f37"}">${t.t(verdictKey)}</div>
<p><strong>${t.t("report.decision")}:</strong> ${t.formatDecision(report.risk.decision)} · <strong>${t.t("report.riskLevel")}:</strong> ${t.formatRiskLevel(report.risk.overallRiskLevel)}</p>

<h2>${t.t("riskMatrix")}</h2>
<table><thead><tr><th>${t.t("report.category")}</th>${riskLevels.map(rl => `<th>${t.formatRiskLevel(rl as any)}</th>`).join("")}</tr></thead>
<tbody>${matrixRows}</tbody></table>

<h2>${t.t("attackSurface")}</h2>
<table><thead><tr><th>${t.t("report.category")}</th><th>${t.t("total")}</th><th>Highlights</th></tr></thead>
<tbody>${surfaceRows}</tbody></table>

<h2>${t.t("report.findings")}</h2>
${findingsHtml}

<h2>${t.t("report.dataFlow")}</h2>
${dataFlowHtml}

<h2>${t.t("finalVerdict")}</h2>
<p style="font-size:18px;font-weight:700">${t.t(verdictKey)}</p>
<p>${t.t("report.rationale")}: ${t.rationale(report.risk.rationale)}</p>

<div class="footer">${t.t("report.generatedAt")}: ${report.generatedAt} · Tool: Repository Security Auditor v${report.toolVersion}</div>
</body></html>`;
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
```

- [ ] **Step 4: Export new functions from index.ts**

Edit `packages/scanner-core/src/index.ts`, add to exports:

```typescript
export { buildAttackSurface, buildRiskMatrix, renderHtmlReport } from "./reporters.js";
export { computeTrustScore, computeFinalVerdict } from "./trustScore.js";
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `npm --workspace @repo-auditor/scanner-core test`
Expected: All tests PASS (some reporter tests may need `buildRiskMatrix` import updated since it's now exported from reporters.ts — check and fix)

- [ ] **Step 6: Commit**

```bash
git add packages/scanner-core/src/reporters.ts packages/scanner-core/src/index.ts packages/scanner-core/tests/reporters.test.ts
git commit -m "feat: add HTML report renderer with trust score, risk matrix, attack surface"
```

---

### Task 6: Integrate into scan pipeline

**Files:**
- Modify: `packages/scanner-core/src/scan.ts`
- Modify: `packages/scanner-core/tests/scan.test.ts`

- [ ] **Step 1: Update scan.ts to compute attackSurface, trustScore, render html**

Edit `packages/scanner-core/src/scan.ts`:

```typescript
import {
  buildAttackSurface,
  buildRiskMatrix,
  renderDecisionRecord,
  renderHtmlReport,
  renderJsonReport,
  renderMarkdownReport,
  renderMermaidDataFlow,
  renderRemediationList,
  renderSarifReport
} from "./reporters.js";
import { computeTrustScore } from "./trustScore.js";
```

Update `scanTarget`:

```typescript
  const inventory = await buildInventory(scanPath);
  const findings = runRules(inventory, options.extraRules);
  const dataFlow = buildDataFlowGraph(inventory, findings);
  const lang = options.language ?? "zh-TW";
  const risk = assessRisk(findings, lang);
  const attackSurface = buildAttackSurface(inventory);
  const report: AuditReport = {
    target,
    findings,
    dataFlow,
    risk,
    attackSurface,
    generatedAt: new Date().toISOString(),
    toolVersion: "0.1.0"
  };
  const trustScore = computeTrustScore(report);

  return {
    report,
    outputs: renderOutputs(report, trustScore, options.outputFormats, lang)
  };
```

Update `renderOutputs` signature:

```typescript
type ScanOutputName = OutputFormat | "decision" | "remediation";

function renderOutputs(report: AuditReport, trustScore: number, outputFormats: OutputFormat[], lang: Language = "zh-TW"): ScanResult["outputs"] {
  ...
  if (selectedFormats.has("html")) {
    outputs.html = renderHtmlReport(report, trustScore, buildRiskMatrix(report.findings), lang);
  }
  ...
}
```

- [ ] **Step 2: Update ScanOutputName type**

Since `html` is now possible, ensure `ScanOutputName` includes it:

```typescript
export type ScanOutputName = OutputFormat | "decision" | "remediation";
// "html" is already in OutputFormat, so this is fine
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `npm --workspace @repo-auditor/scanner-core test`
Expected: All tests PASS. The scan.test.ts may need `attackSurface` added to mock reports — fix if so.

- [ ] **Step 4: Commit**

```bash
git add packages/scanner-core/src/scan.ts
git commit -m "feat: integrate trust score, attack surface, and HTML output into scan pipeline"
```

---

### Task 7: Fix test fixtures that lack attackSurface

**Files:**
- Modify: `packages/scanner-core/tests/reporters.test.ts`
- Modify: `packages/scanner-core/tests/scan.test.ts`
- Modify (possibly): `packages/ai-review/tests/review.test.ts`
- Modify (possibly): `apps/electron/tests/ipc.test.ts`

- [ ] **Step 1: Find all test reports missing attackSurface**

Run: `rg 'AuditReport' packages/ apps/electron/tests/ --type-add 'ts:*.ts' --type ts -l`

For each file, search for `AuditReport` interface usage. Add `attackSurface: []` to every test report object.

- [ ] **Step 2: Fix each test file**

For each test that constructs an `AuditReport`, add `attackSurface: []` to the object literal.

- [ ] **Step 3: Run all tests**

Run: `npm test`
Expected: All 79+ tests PASS (now with attackSurface field in test fixtures)

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "fix: add attackSurface to test fixture reports"
```

---

### Task 8: Update Electron UI for HTML output

**Files:**
- Modify: `apps/electron/src/renderer/index.html`
- Modify: `apps/electron/tests/ipc.test.ts`

- [ ] **Step 1: Add HTML checkbox to output formats**

In `apps/electron/src/renderer/index.html`, add a checkbox for HTML next to the existing ones (around line 300):

```html
<label class="check"><input type="checkbox" name="format" value="html" checked /> HTML</label>
```

- [ ] **Step 2: Update ipc.test.ts output formats list**

Edit `apps/electron/tests/ipc.test.ts`:

```typescript
expect(outputFormats).toEqual(["markdown", "json", "mermaid", "sarif", "html"]);
```

- [ ] **Step 3: Build and run Electron tests**

Run: `npm --workspace apps/electron test`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add apps/electron/src/renderer/index.html apps/electron/tests/ipc.test.ts
git commit -m "feat: add HTML output format checkbox in Electron UI"
```

---

### Task 9: Add text renderers for risk matrix and attack surface (Markdown integration)

**Files:**
- Modify: `packages/scanner-core/src/reporters.ts`
- Modify: `packages/scanner-core/tests/reporters.test.ts`

- [ ] **Step 1: Add text-based risk matrix renderer for Markdown reports**

Add to `packages/scanner-core/src/reporters.ts`:

```typescript
export function renderRiskMatrixText(matrix: Record<string, Record<string, number>>, t: ReturnType<typeof createTranslator>): string {
  const riskLevels = ["Critical", "High", "Medium", "Low"];
  const header = `| ${t.t("report.category")} | ${riskLevels.map(rl => t.formatRiskLevel(rl as any)).join(" | ")} |\n`;
  const sep = `|${riskLevels.map(() => "---|").join("")}\n`;
  let body = "";
  for (const [cat, counts] of Object.entries(matrix).sort()) {
    const cells = riskLevels.map(rl => counts[rl] ?? "—").join(" | ");
    body += `| ${t.formatCategory(cat as any)} | ${cells} |\n`;
  }
  return header + sep + body;
}
```

- [ ] **Step 2: Integrate into renderMarkdownReport**

Add to `renderMarkdownReport`, after the summary section:

```typescript
const matrix = buildRiskMatrix(report.findings);
const matrixText = renderRiskMatrixText(matrix, t);
// Add matrixText to the markdown output
```

- [ ] **Step 3: Run tests**

Run: `npm --workspace @repo-auditor/scanner-core test`
Expected: All PASS

- [ ] **Step 4: Commit**

```bash
git add packages/scanner-core/src/reporters.ts packages/scanner-core/tests/reporters.test.ts
git commit -m "feat: add risk matrix table to Markdown report"
```
