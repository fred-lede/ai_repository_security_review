import { createTranslator, type Language } from "./i18n.js";
import type { AttackSurfaceEntry, AuditReport, DataFlowGraph, Finding } from "./types.js";

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
