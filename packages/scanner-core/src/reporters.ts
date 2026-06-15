import { createTranslator, type Language } from "./i18n.js";
import type { AttackSurfaceEntry, AuditReport, DataFlowGraph, Finding, FindingCategory, RiskLevel } from "./types.js";
import { computeTrustScore, computeFinalVerdict } from "./trustScore.js";

export function renderMarkdownReport(report: AuditReport, lang: Language = "zh-TW"): string {
  const t = createTranslator(lang);
  return [
    `# ${t.t("report.title")}`,
    "",
    `## ${t.t("report.summary")}`,
    "",
    `- ${t.t("report.riskLevel")}：${t.formatRiskLevel(report.risk.overallRiskLevel)}`,
    `- ${t.t("report.decision")}：${t.formatDecision(report.risk.decision)}`,
    `- ${t.t("report.rationale")}：${t.rationale(report.risk.rationale)}`,
    "",
    `## ${t.t("report.scope")}`,
    "",
    `- ${t.t("report.target")}：${report.target.source}`,
    `- ${t.t("report.targetType")}：${report.target.type}`,
    `- ${t.t("report.networkUsed")}：${report.target.networkUsed ? t.t("report.yes") : t.t("report.no")}`,
    `- ${t.t("report.generatedAt")}：${report.generatedAt}`,
    "",
    `## ${t.t("report.findings")}`,
    "",
    ...report.findings.flatMap((finding) => renderFinding(finding, t)),
    "",
    `## ${t.t("riskMatrix")}`,
    "",
    renderRiskMatrixText(buildRiskMatrix(report), t),
    "",
    `## ${t.t("attackSurface")}`,
    "",
    ...buildAttackSurface(report).flatMap(entry => [
      `- **${t.category(entry.category as FindingCategory)}** (${entry.count})`,
      ...entry.highlights.map(fp => `  - \`${fp}\``)
    ]),
    "",
    `## ${t.t("report.dataFlow")}`,
    "",
    "```mermaid",
    renderMermaidDataFlow(report.dataFlow),
    "```",
    "",
    `## ${t.t("report.remediation")}`,
    "",
    ...report.findings.map((finding) => `- ${finding.id}：${t.recommendedFix(finding.recommendedFix)}`)
  ].join("\n");
}

export function renderMermaidDataFlow(graph: DataFlowGraph): string {
  const lines = ["flowchart LR"];
  const nodeIds = new Map(graph.nodes.map((node, index) => [node.id, `n${index}`]));

  for (const node of graph.nodes) {
    const shape = node.leavesMachine
      ? `["${escapeMermaid(node.label)}"]:::external`
      : `["${escapeMermaid(node.label)}"]`;
    lines.push(`  ${nodeIds.get(node.id)}${shape}`);
  }

  for (const edge of graph.edges) {
    const from = nodeIds.get(edge.from);
    const to = nodeIds.get(edge.to);

    if (from && to) {
      lines.push(`  ${from} -->|"${escapeMermaid(edge.label)}"| ${to}`);
    }
  }

  lines.push("  classDef external fill:#fee2e2,stroke:#dc2626,stroke-width:2px");
  return lines.join("\n");
}

export function renderJsonReport(report: AuditReport, _lang?: Language): string {
  return JSON.stringify(report, null, 2);
}

export function renderSarifReport(report: AuditReport, _lang?: Language): string {
  const rules = report.findings.map((finding) => ({
    id: sarifRuleId(finding),
    name: finding.category,
    shortDescription: { text: finding.category },
    fullDescription: { text: finding.explanation },
    help: { text: finding.recommendedFix },
    properties: {
      category: finding.category,
      riskLevel: finding.riskLevel,
      confidence: finding.confidence,
      evidenceTags: finding.evidenceTags
    }
  }));

  const results = report.findings.map((finding) => ({
    ruleId: sarifRuleId(finding),
    level: sarifLevel(finding),
    message: { text: finding.explanation },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: finding.filePath },
          region: {
            startLine: finding.lineStart,
            endLine: finding.lineEnd
          }
        }
      }
    ],
    properties: {
      riskLevel: finding.riskLevel,
      category: finding.category,
      confidence: finding.confidence,
      evidenceTags: finding.evidenceTags,
      recommendedFix: finding.recommendedFix,
      codeSnippet: finding.codeSnippet
    }
  }));

  return JSON.stringify(
    {
      version: "2.1.0",
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      runs: [
        {
          tool: {
            driver: {
              name: "repository-security-auditor",
              version: report.toolVersion,
              informationUri: "https://github.com/openai/codex",
              rules
            }
          },
          results
        }
      ]
    },
    null,
    2
  );
}

type RemediationEntry = {
  id: string;
  riskLevel: string;
  localizedRiskLevel: string;
  filePath: string;
  lineStart: number;
  explanation: string;
  recommendedFix: string;
  localizedRecommendedFix: string;
  decisionRequired: boolean;
};

export function renderRemediationList(report: AuditReport, lang: Language = "zh-TW"): string {
  const t = createTranslator(lang);
  return JSON.stringify(
    report.findings.map(
      (finding): RemediationEntry => ({
        id: finding.id,
        riskLevel: finding.riskLevel,
        localizedRiskLevel: t.riskLevel(finding.riskLevel),
        filePath: finding.filePath,
        lineStart: finding.lineStart,
        explanation: finding.explanation,
        recommendedFix: finding.recommendedFix,
        localizedRecommendedFix: t.recommendedFix(finding.recommendedFix),
        decisionRequired: report.risk.blockingFindingIds.includes(finding.id)
      })
    ),
    null,
    2
  );
}

export function renderDecisionRecord(report: AuditReport, lang: Language = "zh-TW"): string {
  const t = createTranslator(lang);
  return JSON.stringify(
    {
      decision: report.risk.decision,
      overallRiskLevel: report.risk.overallRiskLevel,
      rationale: report.risk.rationale,
      localizedSummary: {
        decision: t.decision(report.risk.decision),
        overallRiskLevel: t.riskLevel(report.risk.overallRiskLevel),
        rationale: t.rationale(report.risk.rationale)
      },
      blockingFindingIds: report.risk.blockingFindingIds,
      blockingFindings: report.findings
        .filter((finding) => report.risk.blockingFindingIds.includes(finding.id))
        .map((finding) => ({
          id: finding.id,
          riskLevel: finding.riskLevel,
          localizedRiskLevel: t.riskLevel(finding.riskLevel),
          category: finding.category,
          localizedCategory: t.category(finding.category),
          filePath: finding.filePath,
          lineStart: finding.lineStart,
          lineEnd: finding.lineEnd,
          codeSnippet: finding.codeSnippet,
          explanation: finding.explanation,
          localizedExplanation: t.explanation(finding.explanation),
          recommendedFix: finding.recommendedFix,
          localizedRecommendedFix: t.recommendedFix(finding.recommendedFix),
          evidenceTags: finding.evidenceTags,
          confidence: finding.confidence,
          dataFlowId: finding.dataFlowId,
          source: finding.source,
          sink: finding.sink,
          dataFlowNodeIds: report.dataFlow.nodes
            .filter((node) => node.id.includes(`${finding.filePath}:${finding.lineStart}`) || node.label.includes(finding.filePath))
            .map((node) => node.id),
          dataFlowEdgeIds: report.dataFlow.edges
            .filter((edge) => edge.findingIds.includes(finding.id))
            .map((edge) => edge.id)
        })),
      requiredFixes: report.findings
        .filter((finding) => report.risk.blockingFindingIds.includes(finding.id))
        .map((finding) => finding.recommendedFix),
      recommendedFixes: report.findings.map((finding) => finding.recommendedFix),
      acceptedRisks: [],
      residualRisk: report.risk.residualRisk,
      scanLimitations: report.risk.scanLimitations,
      generatedAt: report.generatedAt
    },
    null,
    2
  );
}

function renderFinding(finding: Finding, t: ReturnType<typeof createTranslator>): string[] {
  return [
    `### ${finding.id}：${t.category(finding.category)} (${finding.category})`,
    "",
    `- ${t.t("report.riskLevelLabel")}：${t.formatRiskLevel(finding.riskLevel)}`,
    `- ${t.t("report.filePath")}：${finding.filePath}:${finding.lineStart}`,
    `- ${t.t("report.confidence")}：${finding.confidence}`,
    "",
    `${t.t("report.codeSnippet")}：`,
    "",
    "```text",
    finding.codeSnippet,
    "```",
    "",
    `${t.t("report.explanation")}：${t.explanation(finding.explanation)}`,
    "",
    `${t.t("report.recommendedFix")}：${t.recommendedFix(finding.recommendedFix)}`,
    ""
  ];
}

function sarifRuleId(finding: Finding): string {
  return `${finding.category}/${finding.id}`;
}

function sarifLevel(finding: Finding): "error" | "warning" | "note" {
  if (finding.riskLevel === "Critical" || finding.riskLevel === "High") {
    return "error";
  }

  if (finding.riskLevel === "Medium") {
    return "warning";
  }

  return "note";
}

function escapeMermaid(value: string): string {
  return value.replace(/"/g, "'");
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export interface RiskMatrixRow {
  category: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export function buildRiskMatrix(report: AuditReport): RiskMatrixRow[] {
  const matrix = new Map<string, RiskMatrixRow>();

  for (const finding of report.findings) {
    const cat = finding.category;
    let row = matrix.get(cat);
    if (!row) {
      row = { category: cat, critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
      matrix.set(cat, row);
    }
    switch (finding.riskLevel) {
      case "Critical": row.critical++; break;
      case "High": row.high++; break;
      case "Medium": row.medium++; break;
      case "Low": row.low++; break;
      case "Info": row.info++; break;
    }
    row.total++;
  }

  const rows = Array.from(matrix.values());

  const total: RiskMatrixRow = { category: "Total", critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  for (const row of rows) {
    total.critical += row.critical;
    total.high += row.high;
    total.medium += row.medium;
    total.low += row.low;
    total.info += row.info;
    total.total += row.total;
  }
  rows.push(total);

  return rows;
}

export function renderRiskMatrixText(matrix: RiskMatrixRow[], t: ReturnType<typeof createTranslator>): string {
  const header = `| ${t.t("report.category")} | ${t.riskLevel("Critical")} | ${t.riskLevel("High")} | ${t.riskLevel("Medium")} | ${t.riskLevel("Low")} | ${t.riskLevel("Info")} | ${t.t("total")} |`;
  const separator = "|---|---|---|---|---|---|---|";
  const rows = matrix.map(row => {
    const catName = row.category === "Total" ? `**${t.t("total")}**` : t.category(row.category as FindingCategory);
    return `| ${catName} | ${row.critical} | ${row.high} | ${row.medium} | ${row.low} | ${row.info} | **${row.total}** |`;
  });
  return [header, separator, ...rows].join("\n");
}

export function buildAttackSurface(report: AuditReport): AttackSurfaceEntry[] {
  const groups = new Map<string, { count: number; highlights: string[] }>();

  for (const finding of report.findings) {
    const cat = finding.category;
    let entry = groups.get(cat);
    if (!entry) {
      entry = { count: 0, highlights: [] };
      groups.set(cat, entry);
    }
    entry.count++;
    if (!entry.highlights.includes(finding.filePath) && entry.highlights.length < 5) {
      entry.highlights.push(finding.filePath);
    }
  }

  const entries: AttackSurfaceEntry[] = [];
  for (const [category, data] of groups) {
    entries.push({ category, count: data.count, highlights: data.highlights });
  }

  entries.sort((a, b) => b.count - a.count);
  return entries;
}

export function renderHtmlReport(report: AuditReport, lang: Language = "zh-TW"): string {
  const t = createTranslator(lang);
  const trustScoreData = computeTrustScore(report.risk);
  const verdictKey = computeFinalVerdict(report.risk);

  const trustScoreColor = trustScoreData.raw >= 80 ? "#198754"
    : trustScoreData.raw >= 60 ? "#0d6efd"
    : trustScoreData.raw >= 40 ? "#ffc107"
    : trustScoreData.raw >= 20 ? "#fd7e14"
    : "#dc3545";

  const matrix = buildRiskMatrix(report);
  const attackSurface = buildAttackSurface(report);

  const severityOrder: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  const sortedFindings = [...report.findings].sort(
    (a, b) => (severityOrder[a.riskLevel] ?? 99) - (severityOrder[b.riskLevel] ?? 99)
  );

  const mermaid = renderMermaidDataFlow(report.dataFlow);

  const riskBadgeHtml = (level: RiskLevel): string => {
    const colors: Record<string, string> = {
      Critical: "#dc3545",
      High: "#fd7e14",
      Medium: "#ffc107",
      Low: "#0dcaf0",
      Info: "#6c757d"
    };
    const bg = colors[level] ?? "#6c757d";
    const textColor = level === "Medium" ? "#212529" : "#fff";
    return `<span class="risk-badge" style="background:${bg};color:${textColor}">${escapeHtml(t.riskLevel(level))}</span>`;
  };

  return `<!DOCTYPE html>
<html lang="${lang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(t.t("report.title"))}</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#212529;background:#fff;line-height:1.6;padding:2rem;max-width:1200px;margin:0 auto}
h1{font-size:1.75rem;margin-bottom:0.5rem;color:#1a1a2e}
h2{font-size:1.25rem;margin:2rem 0 0.75rem;color:#16213e;border-bottom:2px solid #e9ecef;padding-bottom:0.25rem}
.meta{color:#6c757d;font-size:0.875rem;margin-bottom:1.5rem}
.card{background:#f8f9fa;border:1px solid #dee2e6;border-radius:8px;padding:1rem;margin-bottom:1rem}
.card p{margin:0.25rem 0}
.score-card{text-align:center;padding:2rem;background:#f8f9fa;border-radius:12px;border:1px solid #dee2e6;margin-bottom:1rem}
.score-value{font-size:4rem;font-weight:800;line-height:1}
.score-badge{display:inline-block;padding:0.35rem 1.25rem;border-radius:999px;color:#fff;font-weight:700;font-size:0.875rem;margin:0.75rem 0;text-transform:uppercase;letter-spacing:0.05em}
.verdict{font-size:1.1rem;margin-top:0.5rem}
table{width:100%;border-collapse:collapse;margin-bottom:1rem}
th,td{padding:0.5rem 0.75rem;border:1px solid #dee2e6;text-align:left;font-size:0.875rem}
th{background:#f8f9fa;font-weight:600;white-space:nowrap}
.total-row td{font-weight:700;background:#f8f9fa;border-top:2px solid #dee2e6}
.cell-critical{background:#dc3545;color:#fff;font-weight:700;text-align:center}
.cell-high{background:#fd7e14;color:#fff;font-weight:700;text-align:center}
.cell-medium{background:#ffc107;color:#212529;font-weight:700;text-align:center}
.cell-low{background:#0dcaf0;color:#fff;font-weight:700;text-align:center}
.cell-info{background:#6c757d;color:#fff;font-weight:700;text-align:center}
.risk-badge{display:inline-block;padding:0.15rem 0.5rem;border-radius:4px;color:#fff;font-size:0.75rem;font-weight:600;white-space:nowrap}
.attack-entry{margin-bottom:0.75rem;padding:0.75rem;background:#f8f9fa;border-radius:6px;border:1px solid #e9ecef}
.attack-entry h3{font-size:1rem;margin-bottom:0.25rem}
.attack-entry .count{color:#6c757d;font-size:0.875rem}
.attack-entry ul{list-style:none;padding-left:1rem;margin-top:0.25rem}
.attack-entry li{font-family:'SF Mono','Fira Code',monospace;font-size:0.8125rem;color:#495057;margin:0.125rem 0}
.attack-entry li::before{content:"\\2022 ";color:#adb5bd}
pre{background:#f8f9fa;border:1px solid #dee2e6;border-radius:8px;padding:1rem;overflow-x:auto;font-family:'SF Mono','Fira Code','Consolas',monospace;font-size:0.8125rem;line-height:1.5}
.tag{display:inline-block;padding:0.1rem 0.35rem;background:#e9ecef;border-radius:3px;font-size:0.6875rem;color:#495057;margin:0.1rem;white-space:nowrap}
footer{margin-top:2rem;padding-top:1rem;border-top:1px solid #dee2e6;color:#6c757d;font-size:0.8125rem;text-align:center}
@media(max-width:768px){body{padding:1rem}table{font-size:0.75rem}th,td{padding:0.25rem 0.5rem}}@media print{body{max-width:none;width:170mm;margin:0 auto;padding:10mm 15mm}section{break-before:page}section:first-of-type{break-before:avoid}.card,.attack-entry,table{break-inside:avoid}table thead{display:table-header-group}tr{break-inside:avoid}}
</style>
</head>
<body>

<header>
<h1>${escapeHtml(t.t("report.title"))}</h1>
<p class="meta">${escapeHtml(t.t("report.generatedAt"))}: ${escapeHtml(report.generatedAt)} | Tool Version: ${escapeHtml(report.toolVersion)}</p>
</header>

<section id="summary">
<h2>${escapeHtml(t.t("report.summary"))}</h2>
<div class="card">
<p><strong>${escapeHtml(t.t("report.riskLevel"))}:</strong> ${escapeHtml(t.formatRiskLevel(report.risk.overallRiskLevel))}</p>
<p><strong>${escapeHtml(t.t("report.decision"))}:</strong> ${escapeHtml(t.formatDecision(report.risk.decision))}</p>
<p><strong>${escapeHtml(t.t("report.rationale"))}:</strong> ${escapeHtml(t.rationale(report.risk.rationale))}</p>
</div>
</section>

<section id="trust-score">
<h2>${escapeHtml(t.t("trustScore"))}</h2>
<div class="score-card">
<div class="score-value" style="color:${trustScoreColor}">${trustScoreData.raw}</div>
<div class="score-badge" style="background:${trustScoreColor}">${escapeHtml(t.t(trustScoreData.label))}</div>
<div class="verdict"><strong>${escapeHtml(t.t("finalVerdict"))}:</strong> ${escapeHtml(t.t(verdictKey))}</div>
</div>
</section>

<section id="risk-matrix">
<h2>${escapeHtml(t.t("riskMatrix"))}</h2>
<table>
<thead>
<tr>
<th>${escapeHtml(t.t("report.category"))}</th>
<th>${escapeHtml(t.riskLevel("Critical"))}</th>
<th>${escapeHtml(t.riskLevel("High"))}</th>
<th>${escapeHtml(t.riskLevel("Medium"))}</th>
<th>${escapeHtml(t.riskLevel("Low"))}</th>
<th>${escapeHtml(t.riskLevel("Info"))}</th>
<th>${escapeHtml(t.t("total"))}</th>
</tr>
</thead>
<tbody>
${matrix.map(row => {
  const isTotal = row.category === "Total";
  const catName = isTotal ? t.t("total") : t.category(row.category as FindingCategory);
  return `<tr${isTotal ? ' class="total-row"' : ""}>
<td>${escapeHtml(catName)}</td>
<td${row.critical > 0 ? ' class="cell-critical"' : ""}>${row.critical}</td>
<td${row.high > 0 ? ' class="cell-high"' : ""}>${row.high}</td>
<td${row.medium > 0 ? ' class="cell-medium"' : ""}>${row.medium}</td>
<td${row.low > 0 ? ' class="cell-low"' : ""}>${row.low}</td>
<td${row.info > 0 ? ' class="cell-info"' : ""}>${row.info}</td>
<td><strong>${row.total}</strong></td>
</tr>`;
}).join("\n")}
</tbody>
</table>
</section>

<section id="attack-surface">
<h2>${escapeHtml(t.t("attackSurface"))}</h2>
${attackSurface.map(entry => `
<div class="attack-entry">
<h3>${escapeHtml(t.category(entry.category as FindingCategory))}</h3>
<p class="count">${entry.count} finding${entry.count !== 1 ? "s" : ""}</p>
${entry.highlights.length > 0 ? `<ul>
${entry.highlights.map(fp => `<li>${escapeHtml(fp)}</li>`).join("\n")}
</ul>` : ""}
</div>`).join("\n")}
</section>

<section id="findings">
<h2>${escapeHtml(t.t("report.findings"))}</h2>
<table>
<thead>
<tr>
<th>ID</th>
<th>${escapeHtml(t.t("report.riskLevelLabel"))}</th>
<th>${escapeHtml(t.t("report.category"))}</th>
<th>${escapeHtml(t.t("report.filePath"))}</th>
<th>${escapeHtml(t.t("report.explanation"))}</th>
<th>${escapeHtml(t.t("report.recommendedFix"))}</th>
<th>${escapeHtml(t.t("report.evidenceTags"))}</th>
</tr>
</thead>
<tbody>
${sortedFindings.map(f => `
<tr>
<td><code>${escapeHtml(f.id)}</code></td>
<td>${riskBadgeHtml(f.riskLevel)}</td>
<td>${escapeHtml(t.category(f.category))}</td>
<td><code>${escapeHtml(f.filePath)}:${f.lineStart}</code></td>
<td>${escapeHtml(t.explanation(f.explanation))}</td>
<td>${escapeHtml(t.recommendedFix(f.recommendedFix))}</td>
<td>${f.evidenceTags.map(tag => `<span class="tag">${escapeHtml(tag)}</span>`).join("")}</td>
</tr>`).join("\n")}
</tbody>
</table>
</section>

<section id="data-flow">
<h2>${escapeHtml(t.t("report.dataFlow"))}</h2>
<pre>${escapeHtml(mermaid)}</pre>
</section>

<footer>
<p>${escapeHtml(t.t("report.generatedAt"))}: ${escapeHtml(report.generatedAt)}</p>
</footer>

</body>
</html>`;
}
