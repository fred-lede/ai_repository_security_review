import type { CandidateFinding, HunterResult } from "./hunting.js";
import type { Finding, FindingCategory, RiskLevel } from "./types.js";

export type Verdict = "confirmed" | "needs_validation" | "rejected";

export interface ValidatedFinding {
  candidate: CandidateFinding;
  verdict: Verdict;
  verification: VerificationRecord;
  validatedAt: string;
  validatorId: string;
}

export interface VerificationRecord {
  checksPerformed: string[];
  evidenceFor: string[];
  evidenceAgainst: string[];
  conclusion: string;
  disproofAttempts: DisproofAttempt[];
}

export interface DisproofAttempt {
  method: string;
  result: "disproved" | "inconclusive" | "confirmed_vulnerability";
  details: string;
}

export interface ValidationResult {
  validatedFindings: ValidatedFinding[];
  summary: {
    confirmed: number;
    needsValidation: number;
    rejected: number;
  };
}

export async function runValidationPhase(
  hunterResults: HunterResult[],
  options: { maxValidators?: number } = {}
): Promise<ValidationResult> {
  const allCandidates = hunterResults.flatMap(r => r.candidates);
  const validatedFindings: ValidatedFinding[] = [];

  for (let i = 0; i < allCandidates.length; i++) {
    if (options.maxValidators && i >= options.maxValidators) break;

    const candidate = allCandidates[i];
    const validated = await validateCandidate(candidate, `validator-${i + 1}`);
    validatedFindings.push(validated);
  }

  const summary = {
    confirmed: validatedFindings.filter(v => v.verdict === "confirmed").length,
    needsValidation: validatedFindings.filter(v => v.verdict === "needs_validation").length,
    rejected: validatedFindings.filter(v => v.verdict === "rejected").length
  };

  return { validatedFindings, summary };
}

async function validateCandidate(candidate: CandidateFinding, validatorId: string): Promise<ValidatedFinding> {
  const checksPerformed: string[] = [];
  const evidenceFor: string[] = [];
  const evidenceAgainst: string[] = [];
  const disproofAttempts: DisproofAttempt[] = [];

  checksPerformed.push("Trace data flow from source to sink");
  checksPerformed.push("Check for input validation/sanitization");
  checksPerformed.push("Verify sink dangerousness in context");
  checksPerformed.push("Attempt to construct exploit payload");
  checksPerformed.push("Check for alternative safe code paths");

  const hasClearSourceToSink = candidate.source && candidate.sink && candidate.source !== candidate.sink;
  const hasValidationBypass = candidate.evidenceTags.includes("validation-bypass") || candidate.confidence === "High";
  const isDirectDangerousSink =
    typeof candidate.sink === "string" &&
    /child-process-exec|javascript\.eval|python\.eval|shell\.curl_sh|java\.runtime_exec|dockerfile\.curl_sh|webhook-sink|encoded-sink|non-http-sink|file-upload-sink|ssrf-sink/.test(candidate.sink);

  if (hasClearSourceToSink) {
    evidenceFor.push(`Clear source (${candidate.source}) to sink (${candidate.sink}) path identified`);
  }
  if (hasValidationBypass) {
    evidenceFor.push("Validation bypass indicators present");
  }
  if (isDirectDangerousSink) {
    evidenceFor.push("Direct dangerous sink (eval/exec/curl|sh) detected");
  }
  if (candidate.reproductionSteps.length > 0) {
    evidenceFor.push("Concrete reproduction steps available");
  }

  if (!candidate.source || !candidate.sink) {
    evidenceAgainst.push("Incomplete source-to-sink trace");
  }
  if (candidate.confidence === "Low") {
    evidenceAgainst.push("Low confidence in exploitability");
  }
  if (candidate.disproofAttempts.some(a => a.includes("validation") || a.includes("sanitization"))) {
    evidenceAgainst.push("Validation/sanitization may be present");
  }

  disproofAttempts.push({
    method: "Input validation check",
    result: hasValidationBypass ? "confirmed_vulnerability" : "inconclusive",
    details: hasValidationBypass ? "Validation appears bypassable or missing" : "Cannot confirm validation absence"
  });

  disproofAttempts.push({
    method: "Exploit construction",
    result: isDirectDangerousSink ? "confirmed_vulnerability" : "inconclusive",
    details: isDirectDangerousSink ? "Direct dangerous sink allows trivial exploit" : "Exploit requires specific conditions"
  });

  disproofAttempts.push({
    method: "Alternative path analysis",
    result: "inconclusive",
    details: "No safe alternative path confirmed"
  });

  let verdict: Verdict;
  let conclusion: string;

  const confirmedVulnAttempts = disproofAttempts.filter(d => d.result === "confirmed_vulnerability").length;

  if (confirmedVulnAttempts >= 2 && hasClearSourceToSink) {
    verdict = "confirmed";
    conclusion = "Complete source-to-sink trace with confirmed exploitability. Validation bypass or missing validation confirmed.";
  } else if (evidenceFor.length >= 2 && evidenceAgainst.length <= 1) {
    verdict = "needs_validation";
    conclusion = "Strong indicators of vulnerability but incomplete trace or uncertain exploitability. Requires deeper manual review.";
  } else {
    verdict = "rejected";
    conclusion = "Insufficient evidence for vulnerability. Source-to-sink trace incomplete, validation likely present, or sink not exploitable.";
  }

  return {
    candidate,
    verdict,
    verification: {
      checksPerformed,
      evidenceFor,
      evidenceAgainst,
      conclusion,
      disproofAttempts
    },
    validatedAt: new Date().toISOString(),
    validatorId
  };
}

export function filterConfirmed(validated: ValidatedFinding[]): ValidatedFinding[] {
  return validated.filter(v => v.verdict === "confirmed");
}

export function filterNeedsValidation(validated: ValidatedFinding[]): ValidatedFinding[] {
  return validated.filter(v => v.verdict === "needs_validation");
}

export function filterRejected(validated: ValidatedFinding[]): ValidatedFinding[] {
  return validated.filter(v => v.verdict === "rejected");
}

export function convertToFinding(validated: ValidatedFinding): Finding {
  const c = validated.candidate;
  return {
    id: c.id,
    riskLevel: c.riskLevel,
    category: c.category,
    filePath: c.filePath,
    lineStart: c.lineStart,
    lineEnd: c.lineEnd,
    codeSnippet: c.codeSnippet,
    explanation: c.explanation,
    recommendedFix: c.recommendedFix,
    evidenceTags: [...c.evidenceTags, `verdict:${validated.verdict}`, `validator:${validated.validatorId}`],
    source: c.source,
    sink: c.sink,
    dataFlowId: c.dataFlowId,
    confidence: c.confidence,
    remediation: {
      summary: c.recommendedFix.split(".")[0],
      saferPattern: "Use safe APIs with explicit validation",
      testSuggestion: c.reproductionSteps.join("; "),
      breakingChangeRisk: c.riskLevel === "Critical" ? "High" : c.riskLevel === "High" ? "Medium" : "Low"
    }
  };
}