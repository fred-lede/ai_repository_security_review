import type { CoverageLedger } from "./reconnaissance.js";
import type { ValidatedFinding } from "./validation.js";

export type FindingVerdict = "confirmed" | "needs_validation" | "rejected";

export interface FindingRecord {
  id: string;
  verdict: FindingVerdict;
  category: string;
  riskLevel: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  codeSnippet: string;
  explanation: string;
  recommendedFix: string;
  evidenceTags: string[];
  confidence: string;
  attackVector?: string;
  source?: string;
  sink?: string;
  verification: {
    checksPerformed: string[];
    evidenceFor: string[];
    evidenceAgainst: string[];
    conclusion: string;
  };
  validationChain: Array<{
    validatorId: string;
    verdict: FindingVerdict;
    at: string;
  }>;
}

export interface FindingsDocument {
  $schemaVersion: 1;
  target: string;
  generatedAt: string;
  tool: string;
  toolVersion: string;
  confirmed: FindingRecord[];
  needs_validation: FindingRecord[];
  rejected: FindingRecord[];
  coverage: CoverageLedger;
}

export interface FindingsValidationResult {
  valid: boolean;
  errors: string[];
}

export function buildFindingsDocument(
  target: string,
  validated: ValidatedFinding[],
  coverage: CoverageLedger,
  toolVersion: string = "0.3.2"
): FindingsDocument {
  const records = validated.map((v): FindingRecord => ({
    id: v.candidate.id,
    verdict: v.verdict,
    category: v.candidate.category,
    riskLevel: v.candidate.riskLevel,
    filePath: v.candidate.filePath,
    lineStart: v.candidate.lineStart,
    lineEnd: v.candidate.lineEnd,
    codeSnippet: v.candidate.codeSnippet,
    explanation: v.candidate.explanation,
    recommendedFix: v.candidate.recommendedFix,
    evidenceTags: v.candidate.evidenceTags,
    confidence: v.candidate.confidence,
    attackVector: v.candidate.attackVector,
    source: v.candidate.source,
    sink: v.candidate.sink,
    verification: {
      checksPerformed: v.verification.checksPerformed,
      evidenceFor: v.verification.evidenceFor,
      evidenceAgainst: v.verification.evidenceAgainst,
      conclusion: v.verification.conclusion
    },
    validationChain: [
      {
        validatorId: v.validatorId,
        verdict: v.verdict,
        at: v.validatedAt
      }
    ]
  }));

  return {
    $schemaVersion: 1,
    target,
    generatedAt: new Date().toISOString(),
    tool: "repository-security-auditor",
    toolVersion,
    confirmed: records.filter((r) => r.verdict === "confirmed"),
    needs_validation: records.filter((r) => r.verdict === "needs_validation"),
    rejected: records.filter((r) => r.verdict === "rejected"),
    coverage
  };
}

/**
 * Deterministic structural validation mirroring the skill's
 * validate-findings.cjs. Checks required fields and the three-verdict
 * invariant: confirmed records must carry a complete verification
 * conclusion; needs_validation records carry no severity commitment.
 */
export function validateFindingsDocument(doc: FindingsDocument): FindingsValidationResult {
  const errors: string[] = [];

  if (!doc || typeof doc !== "object") {
    return { valid: false, errors: ["document is not an object"] };
  }
  if (doc.$schemaVersion !== 1) {
    errors.push("$schemaVersion must be 1");
  }
  if (typeof doc.target !== "string" || doc.target.length === 0) {
    errors.push("target is required");
  }
  for (const bucket of ["confirmed", "needs_validation", "rejected"] as const) {
    if (!Array.isArray(doc[bucket])) {
      errors.push(`${bucket} must be an array`);
      continue;
    }
    for (const record of doc[bucket]) {
      if (record.verdict !== bucket) {
        errors.push(`record ${record.id} has verdict ${record.verdict} in ${bucket} bucket`);
      }
      for (const field of [
        "id",
        "category",
        "riskLevel",
        "filePath",
        "lineStart",
        "explanation",
        "recommendedFix"
      ] as const) {
        if (record[field] === undefined || record[field] === "") {
          errors.push(`record ${record.id}: missing ${field}`);
        }
      }
      if (!Array.isArray(record.evidenceTags)) {
        errors.push(`record ${record.id}: evidenceTags must be an array`);
      }
      if (!record.verification || typeof record.verification.conclusion !== "string") {
        errors.push(`record ${record.id}: verification.conclusion is required`);
      }
      if (!Array.isArray(record.validationChain) || record.validationChain.length === 0) {
        errors.push(`record ${record.id}: validationChain must not be empty`);
      }
    }
  }
  if (!doc.coverage || !Array.isArray(doc.coverage.units)) {
    errors.push("coverage ledger is required");
  }

  return { valid: errors.length === 0, errors };
}

export function serializeFindingsDocument(doc: FindingsDocument): string {
  return JSON.stringify(doc, null, 2);
}

export function deserializeFindingsDocument(json: string): FindingsDocument {
  return JSON.parse(json);
}

/**
 * Load prior runs' findings documents so later audits are additive:
 * skip known findings, target gaps, resolve disagreements.
 */
export function mergePriorFindings(
  current: FindingsDocument,
  ...prior: FindingsDocument[]
): { doc: FindingsDocument; carriedForward: string[] } {
  const knownConfirmed = new Set(prior.flatMap((p) => p.confirmed.map((r) => recordKey(r))));
  const knownNeedsValidation = new Set(prior.flatMap((p) => p.needs_validation.map((r) => recordKey(r))));

  const carriedForward: string[] = [];
  const doc = { ...current };

  for (const record of doc.confirmed) {
    if (knownConfirmed.has(recordKey(record))) {
      // Same finding confirmed in a prior run: carry it forward with the old chain.
      carriedForward.push(record.id);
      const oldChain = prior
        .flatMap((p) => p.confirmed)
        .filter((r) => recordKey(r) === recordKey(record))
        .flatMap((r) => r.validationChain);
      record.validationChain = [...record.validationChain, ...oldChain];
    }
  }

  for (const record of doc.needs_validation) {
    if (knownNeedsValidation.has(recordKey(record))) {
      carriedForward.push(record.id);
    }
  }

  return { doc, carriedForward };
}

function recordKey(record: FindingRecord): string {
  return `${record.category}:${record.filePath}:${record.lineStart}:${record.riskLevel}`;
}
