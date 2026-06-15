import type { RiskAssessment } from "./types.js";

export interface TrustScore {
  raw: number;
  label: string;
  explanation: string;
}

export function computeTrustScore(risk: RiskAssessment): TrustScore {
  const { severityCounts, residualRisk, scanLimitations } = risk;

  let raw = 100;

  raw -= (severityCounts["Critical"] ?? 0) * 25;
  raw -= (severityCounts["High"] ?? 0) * 10;
  raw -= (severityCounts["Medium"] ?? 0) * 5;

  if (residualRisk.includes("static")) {
    raw -= 5;
  }

  if (scanLimitations.length > 2) {
    raw -= 5;
  }

  raw = Math.max(0, Math.min(100, raw));

  let label: string;
  let explanation: string;

  if (raw >= 80) {
    label = "trustScoreLabel";
    explanation = "Trusted - no significant security concerns";
  } else if (raw >= 60) {
    label = "trustScoreGenerallySafe";
    explanation = "Generally safe with minor concerns";
  } else if (raw >= 40) {
    label = "trustScoreCaution";
    explanation = "Use with caution - moderate risks detected";
  } else if (raw >= 20) {
    label = "trustScoreHighRisk";
    explanation = "High risk - significant security concerns";
  } else {
    label = "trustScoreCritical";
    explanation = "Critical risk - severe security concerns";
  }

  return { raw, label, explanation };
}

export function computeFinalVerdict(risk: RiskAssessment): string {
  switch (risk.decision) {
    case "Pass":
      return "verdictApproved";
    case "Monitor":
      return "verdictApprovedCaution";
    case "Needs Review":
      return "verdictManualReview";
    case "Block":
      return "verdictBlock";
  }
}
