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

export function renderSarifReport(report: AuditReport): string {
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

export function renderRemediationList(report: AuditReport): string {
  return JSON.stringify(
    report.findings.map((finding) => ({
      id: finding.id,
      riskLevel: finding.riskLevel,
      filePath: finding.filePath,
      lineStart: finding.lineStart,
      explanation: finding.explanation,
      recommendedFix: finding.recommendedFix,
      decisionRequired: report.risk.blockingFindingIds.includes(finding.id)
    })),
    null,
    2
  );
}

export function renderDecisionRecord(report: AuditReport): string {
  return JSON.stringify(
    {
      decision: report.risk.decision,
      overallRiskLevel: report.risk.overallRiskLevel,
      rationale: report.risk.rationale,
      blockingFindingIds: report.risk.blockingFindingIds,
      blockingFindings: report.findings
        .filter((finding) => report.risk.blockingFindingIds.includes(finding.id))
        .map((finding) => ({
          id: finding.id,
          riskLevel: finding.riskLevel,
          category: finding.category,
          filePath: finding.filePath,
          lineStart: finding.lineStart,
          lineEnd: finding.lineEnd,
          codeSnippet: finding.codeSnippet,
          explanation: finding.explanation,
          recommendedFix: finding.recommendedFix,
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
