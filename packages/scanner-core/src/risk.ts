import type { Decision, Finding, FindingCategory, RiskAssessment, RiskLevel } from "./types.js";

const riskOrder: RiskLevel[] = ["Critical", "High", "Medium", "Low", "Info"];

const blockingCategories: FindingCategory[] = [
  "data-exfiltration",
  "credential-leakage",
  "command-injection",
  "remote-code-execution",
  "persistence",
  "postinstall-script",
  "github-actions"
];

export function assessRisk(findings: Finding[]): RiskAssessment {
  const severityCounts = countByRisk(findings);
  const categoryCounts: Partial<Record<FindingCategory, number>> = {};
  const sortedFindings = findings
    .map((finding, index) => ({ finding, index }))
    .sort((a, b) => {
      const riskComparison = riskOrder.indexOf(a.finding.riskLevel) - riskOrder.indexOf(b.finding.riskLevel);
      return riskComparison === 0 ? a.index - b.index : riskComparison;
    })
    .map(({ finding }) => finding);

  for (const finding of findings) {
    categoryCounts[finding.category] = (categoryCounts[finding.category] ?? 0) + 1;
  }

  const blocking = findings.filter(
    (finding) =>
      finding.riskLevel === "Critical" ||
      (finding.riskLevel === "High" &&
        finding.confidence === "High" &&
        (blockingCategories.includes(finding.category) || finding.evidenceTags.includes("exfiltration-candidate")))
  );
  const overallRiskLevel = riskOrder.find((risk) => severityCounts[risk] > 0) ?? "Info";
  const decision: Decision =
    blocking.length > 0
      ? "Block"
      : severityCounts.High > 0 || severityCounts.Medium > 0
        ? "Needs Review"
        : severityCounts.Low > 0
          ? "Monitor"
          : "Pass";

  return {
    overallRiskLevel,
    decision,
    rationale:
      decision === "Block"
        ? "One or more findings can expose secrets, execute commands, persist, or send sensitive data outward."
        : "No blocking deterministic evidence was found in the configured scan scope.",
    topRisks: sortedFindings.slice(0, 3).map((finding) => `${finding.riskLevel}: ${finding.explanation}`),
    severityCounts,
    categoryCounts,
    blockingFindingIds: blocking.map((finding) => finding.id),
    residualRisk:
      "Static analysis cannot prove every runtime path. Review dynamic behavior before trusting high-risk packages.",
    scanLimitations: ["Static analysis only", "No target code execution", "Limited interprocedural taint analysis"]
  };
}

function countByRisk(findings: Finding[]): Record<RiskLevel, number> {
  return {
    Critical: findings.filter((finding) => finding.riskLevel === "Critical").length,
    High: findings.filter((finding) => finding.riskLevel === "High").length,
    Medium: findings.filter((finding) => finding.riskLevel === "Medium").length,
    Low: findings.filter((finding) => finding.riskLevel === "Low").length,
    Info: findings.filter((finding) => finding.riskLevel === "Info").length
  };
}
