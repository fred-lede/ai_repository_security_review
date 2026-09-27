import fs from "node:fs/promises";
import path from "node:path";
import type { FindingRecord, FindingsDocument } from "./structuredOutput.js";

/**
 * Phase 5: independent record verification.
 *
 * The parent orchestrator re-verifies final source claims with a fresh
 * pass that has no knowledge of how the candidate was produced. Each
 * claim is checked against the actual on-disk file content:
 *
 * - snippet-present: the record's codeSnippet (or a distinctive prefix)
 *   exists in the referenced file at the referenced line.
 * - location-valid: the file exists and the line number is in range.
 *
 * A record whose material claims fail verification is demoted from
 * `confirmed` to `needs_validation` and receives a replacement in its
 * validationChain. Replacement records are themselves verified again by
 * the parent before being accepted.
 */

export interface VerificationOutcome {
  recordId: string;
  checks: Array<{ name: string; passed: boolean; detail: string }>;
  demoted: boolean;
  replacement?: FindingRecord;
}

export interface IndependentVerificationResult {
  outcomes: VerificationOutcome[];
  doc: FindingsDocument;
  recordsToReVerify: FindingRecord[];
}

export async function verifyFindingRecords(
  doc: FindingsDocument,
  targetDir: string
): Promise<IndependentVerificationResult> {
  const outcomes: VerificationOutcome[] = [];
  const recordsToReVerify: FindingRecord[] = [];
  const confirmed = [...doc.confirmed];
  const needsValidation = [...doc.needs_validation];

  for (const record of confirmed) {
    const checks = await checkRecordClaims(record, targetDir);
    const allPassed = checks.every((c) => c.passed);

    if (allPassed) {
      record.validationChain.push({
        validatorId: "independent-verifier",
        verdict: "confirmed",
        at: new Date().toISOString()
      });
      outcomes.push({ recordId: record.id, checks, demoted: false });
    } else {
      const replacement: FindingRecord = {
        ...record,
        verdict: "needs_validation",
        riskLevel: "Low",
        evidenceTags: [...record.evidenceTags, "verification-failed"],
        verification: {
          ...record.verification,
          conclusion: `Independent verification failed: ${checks
            .filter((c) => !c.passed)
            .map((c) => c.name)
            .join(", ")}. Material claim could not be reproduced from source; downgraded to needs_validation.`
        },
        validationChain: [
          ...record.validationChain,
          {
            validatorId: "independent-verifier",
            verdict: "needs_validation",
            at: new Date().toISOString()
          }
        ]
      };
      needsValidation.push(replacement);
      recordsToReVerify.push(replacement);
      outcomes.push({ recordId: record.id, checks, demoted: true, replacement });
    }
  }

  const resultDoc: FindingsDocument = {
    ...doc,
    confirmed: confirmed.filter((r) =>
      outcomes.find((o) => o.recordId === r.id)?.demoted ? false : true
    ),
    needs_validation: needsValidation
  };

  return { outcomes, doc: resultDoc, recordsToReVerify };
}

export async function checkRecordClaims(
  record: FindingRecord,
  targetDir: string
): Promise<Array<{ name: string; passed: boolean; detail: string }>> {
  const checks: Array<{ name: string; passed: boolean; detail: string }> = [];
  const fullPath = path.join(targetDir, record.filePath);

  let content: string | null = null;
  try {
    content = await fs.readFile(fullPath, "utf8");
  } catch {
    content = null;
  }

  if (content === null) {
    checks.push({
      name: "location-valid",
      passed: false,
      detail: `file ${record.filePath} not found on disk`
    });
    checks.push({
      name: "snippet-present",
      passed: false,
      detail: "skipped: file unavailable"
    });
    return checks;
  }

  const lines = content.split(/\r?\n/);
  const inRange =
    record.lineStart >= 1 && record.lineStart <= Math.max(lines.length, 1);
  checks.push({
    name: "location-valid",
    passed: inRange,
    detail: inRange
      ? `line ${record.lineStart} within file of ${lines.length} lines`
      : `line ${record.lineStart} out of range (file has ${lines.length} lines)`
  });

  const snippet = record.codeSnippet.trim();
  const marker = snippet.length > 20 ? snippet.slice(0, 40) : snippet;
  let snippetPresent = false;
  let matchedLine = 0;

  if (snippet && inRange) {
    // Prefer matching near the claimed line (±3 lines), else anywhere.
    const near = lines.slice(Math.max(0, record.lineStart - 4), Math.min(lines.length, record.lineStart + 3));
    for (let i = 0; i < near.length; i++) {
      const idx = Math.max(0, record.lineStart - 4) + i;
      if (near[i].trim().includes(marker) || lines[idx].includes(marker)) {
        snippetPresent = true;
        matchedLine = idx + 1;
        break;
      }
    }
    if (!snippetPresent) {
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes(marker)) {
          snippetPresent = true;
          matchedLine = i + 1;
          break;
        }
      }
    }
  }

  checks.push({
    name: "snippet-present",
    passed: snippetPresent || snippet === "",
    detail: snippetPresent
      ? `snippet matched at line ${matchedLine}`
      : `snippet "${marker}" not found in ${record.filePath}`
  });

  return checks;
}

export function isMaterialReplacement(outcome: VerificationOutcome): boolean {
  return outcome.demoted && outcome.replacement !== undefined;
}
