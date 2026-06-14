import type { AuditReport, DataFlowGraph, Finding } from "./types.js";

export function renderMarkdownReport(report: AuditReport): string {
  return [
    "# Repository Security Audit Report",
    "",
    "## Executive Summary",
    "",
    `- Overall Risk Level: ${report.risk.overallRiskLevel}`,
    `- Decision: ${report.risk.decision}`,
    `- Rationale: ${report.risk.rationale}`,
    "",
    "## Scope And Provenance",
    "",
    `- Target: ${report.target.source}`,
    `- Target Type: ${report.target.type}`,
    `- Network Used During Acquisition: ${report.target.networkUsed}`,
    `- Generated At: ${report.generatedAt}`,
    "",
    "## Findings",
    "",
    ...report.findings.flatMap(renderFinding),
    "## Data Flow",
    "",
    "```mermaid",
    renderMermaidDataFlow(report.dataFlow),
    "```",
    "",
    "## Remediation Plan",
    "",
    ...report.findings.map((finding) => `- ${finding.id}: ${finding.recommendedFix}`)
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

export function renderJsonReport(report: AuditReport): string {
  return JSON.stringify(report, null, 2);
}

export function renderDecisionRecord(report: AuditReport): string {
  return JSON.stringify(
    {
      decision: report.risk.decision,
      overallRiskLevel: report.risk.overallRiskLevel,
      rationale: report.risk.rationale,
      blockingFindings: report.risk.blockingFindingIds,
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

function renderFinding(finding: Finding): string[] {
  return [
    `### ${finding.id}: ${finding.category}`,
    "",
    `- Risk Level: ${finding.riskLevel}`,
    `- File Path: ${finding.filePath}:${finding.lineStart}`,
    `- Confidence: ${finding.confidence}`,
    "",
    "Code Snippet:",
    "",
    "```text",
    finding.codeSnippet,
    "```",
    "",
    `Explanation: ${finding.explanation}`,
    "",
    `Recommended Fix: ${finding.recommendedFix}`,
    ""
  ];
}

function escapeMermaid(value: string): string {
  return value.replace(/"/g, "'");
}
