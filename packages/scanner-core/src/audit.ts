import { runReconnaissance, serializeCoverageLedger } from "./reconnaissance.js";
import type { ArchitectureSummary, CoverageLedger } from "./reconnaissance.js";
import { runHuntingPhase, runCoverageCritic } from "./hunting.js";
import type { HunterResult } from "./hunting.js";
import { runValidationPhase, convertToFinding, filterConfirmed, filterNeedsValidation } from "./validation.js";
import type { ValidatedFinding } from "./validation.js";
import {
  buildFindingsDocument,
  validateFindingsDocument,
  mergePriorFindings,
  type FindingsDocument
} from "./structuredOutput.js";
import { verifyFindingRecords, isMaterialReplacement } from "./independentVerification.js";
import { buildReportBundle } from "./targetNeutralReporting.js";
import type { ReportBundle } from "./targetNeutralReporting.js";
import type { Finding, AuditReport } from "./types.js";
import type { ProjectInventory } from "./inventory.js";

export interface AuditOptions {
  target: string;
  targetDir: string;
  inventory: ProjectInventory;
  /** Optional prior findings documents for additive runs. */
  priorFindings?: FindingsDocument[];
  maxHunters?: number;
  maxValidators?: number;
  toolVersion?: string;
}

export interface AuditResult {
  architecture: ArchitectureSummary;
  hunterResults: HunterResult[];
  validated: ValidatedFinding[];
  findingsDoc: FindingsDocument;
  verification: {
    outcomes: import("./independentVerification.js").VerificationOutcome[];
    reVerifiedCount: number;
  };
  reports: ReportBundle;
  /** Confirmed+validated findings projected into the classic Finding shape. */
  classicFindings: Finding[];
  coverageLedgerJson: string;
}

/** Deterministic structural validation for the coverage ledger. */
export function validateCoverageLedger(ledger: CoverageLedger): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  if (!ledger || typeof ledger !== "object") {
    return { valid: false, errors: ["ledger is not an object"] };
  }
  if (typeof ledger.version !== "number") {
    errors.push("ledger.version must be a number");
  }
  if (!Array.isArray(ledger.units) || ledger.units.length === 0) {
    errors.push("ledger.units must be a non-empty array");
  } else {
    const seen = new Set<string>();
    for (const unit of ledger.units) {
      if (typeof unit.id !== "string" || unit.id.length === 0) {
        errors.push("ledger unit missing id");
      } else if (seen.has(unit.id)) {
        errors.push(`duplicate ledger unit id: ${unit.id}`);
      } else {
        seen.add(unit.id);
      }
      if (!["unexplored", "in-progress", "covered", "gap-detected"].includes(unit.status)) {
        errors.push(`unit ${unit.id} has unknown status: ${String(unit.status)}`);
      }
      if (!Array.isArray(unit.findings)) {
        errors.push(`unit ${unit.id} findings must be an array`);
      }
      // A covered unit with zero findings is a gap, not coverage.
      if (unit.status === "covered" && unit.findings.length === 0) {
        errors.push(`unit ${unit.id} marked covered but has no findings`);
      }
    }
  }
  return { valid: errors.length === 0, errors };
}

/**
 * Orchestrate the full six-phase audit:
 * 1. reconnaissance  2. coverage-led hunting  3. candidate validation
 * 4. structured output  5. independent verification  6. target-neutral reporting
 */
export async function runFullAudit(options: AuditOptions): Promise<AuditResult> {
  // Phase 1: reconnaissance
  const architecture = await runReconnaissance(options.targetDir, options.inventory);
  const ledgerValidation = validateCoverageLedger(architecture.coverageLedger);
  if (!ledgerValidation.valid) {
    throw new Error(`coverage ledger failed validation: ${ledgerValidation.errors.join("; ")}`);
  }

  let ledger = architecture.coverageLedger;

  // Phase 2: coverage-led hunting
  const { results: hunterResults, updatedLedger } = await runHuntingPhase(
    architecture,
    options.inventory,
    ledger,
    { maxHunters: options.maxHunters, targetDir: options.targetDir }
  );
  ledger = updatedLedger;

  // Coverage critic: find gaps and mark them
  const gaps = runCoverageCritic(ledger, architecture);
  for (const gap of gaps) {
    ledger = {
      ...ledger,
      units: ledger.units.map((u) => (u.id === gap.id ? gap : u)),
      lastUpdated: new Date().toISOString()
    };
  }
  const gapCheck = validateCoverageLedger(ledger);
  if (!gapCheck.valid) {
    throw new Error(`coverage ledger failed validation after hunting: ${gapCheck.errors.join("; ")}`);
  }

  // Phase 3: candidate validation (fresh verifier per candidate)
  const { validatedFindings } = await runValidationPhase(hunterResults, {
    maxValidators: options.maxValidators
  });

  // Phase 4: structured output
  let doc = buildFindingsDocument(options.target, validatedFindings, ledger, options.toolVersion ?? "0.3.2");
  if (options.priorFindings && options.priorFindings.length > 0) {
    const merged = mergePriorFindings(doc, ...options.priorFindings);
    doc = merged.doc;
  }
  const docValidation = validateFindingsDocument(doc);
  if (!docValidation.valid) {
    throw new Error(`findings document failed validation: ${docValidation.errors.join("; ")}`);
  }

  // Phase 5: independent record verification
  const verification = await verifyFindingRecords(doc, options.targetDir);
  let finalDoc = verification.doc;

  // Material replacements (demoted records) receive ANOTHER independent verifier pass.
  let reVerifiedCount = 0;
  if (verification.recordsToReVerify.length > 0) {
    const secondPass = await verifyFindingRecords(finalDoc, options.targetDir);
    finalDoc = secondPass.doc;
    reVerifiedCount = secondPass.recordsToReVerify.length;
  }

  const finalValidation = validateFindingsDocument(finalDoc);
  if (!finalValidation.valid) {
    throw new Error(`final findings document failed validation: ${finalValidation.errors.join("; ")}`);
  }

  // Phase 6: target-neutral reporting
  const reports = buildReportBundle(finalDoc, architecture);

  // Project confirmed findings into the classic Finding shape for the existing
  // report pipeline (markdown/json/sarif/html/pdf all keep working).
  const confirmed = filterConfirmed(
    validatedFindings.map((v, i) => ({
      ...v,
      // reflect independent-verification demotions:
      verdict:
        verification.outcomes.find((o) => o.recordId === v.candidate.id)?.demoted === true
          ? ("needs_validation" as const)
          : v.verdict
    }))
  );
  const needsValidation = filterNeedsValidation(validatedFindings);
  const classicFindings: Finding[] = [
    ...confirmed.map(convertToFinding),
    ...needsValidation.map(convertToFinding)
  ];

  return {
    architecture,
    hunterResults,
    validated: validatedFindings,
    findingsDoc: finalDoc,
    verification: {
      outcomes: verification.outcomes,
      reVerifiedCount
    },
    reports,
    classicFindings,
    coverageLedgerJson: serializeCoverageLedger(ledger)
  };
}

/**
 * Attach audit results to a classic AuditReport for the existing report
 * pipeline (markdown/json/sarif/html/pdf keep working).
 *
 * Deduplicates by (category, filePath, lineStart) so a finding already
 * present from the deterministic scan is not emitted twice.
 */
export function attachAuditToReport(
  report: AuditReport,
  audit: AuditResult
): AuditReport {
  const existing = new Set(
    report.findings.map((f) => `${f.category}\0${f.filePath}\0${f.lineStart}`)
  );
  const additions = audit.classicFindings.filter(
    (f) => !existing.has(`${f.category}\0${f.filePath}\0${f.lineStart}`)
  );
  return { ...report, findings: [...report.findings, ...additions] };
}
