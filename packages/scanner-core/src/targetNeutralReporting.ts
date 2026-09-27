import type { FindingRecord, FindingsDocument } from "./structuredOutput.js";
import type { ArchitectureSummary, CoverageLedger } from "./reconnaissance.js";

/**
 * Phase 6: target-neutral reporting.
 *
 * Derives REPORT.md, FINDINGS-DETAIL.md, and NEEDS-VALIDATION.md from
 * the verified records and the coverage ledger. The reports are
 * "target-neutral": they never embed target-specific metadata beyond
 * what is in the records themselves, so the same derivation logic works
 * for any repository and the output stays reproducible.
 */

export interface ReportBundle {
  reportMd: string;
  findingsDetailMd: string;
  needsValidationMd: string;
}

const severityOrder: Record<string, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
  Info: 4
};

export function buildReportBundle(
  doc: FindingsDocument,
  architecture: ArchitectureSummary
): ReportBundle {
  const covered = doc.coverage.units.filter((u) => u.status === "covered").length;
  const gaps = doc.coverage.units.filter((u) => u.status === "gap-detected").length;
  const total = doc.coverage.units.length;

  const reportMd = [
    `# Security Audit Report`,
    ``,
    `Target: \`${doc.target}\`  ·  Generated: ${doc.generatedAt}  ·  Tool ${doc.tool} v${doc.toolVersion}`,
    ``,
    `## Executive Summary`,
    ``,
    `- Application type: **${architecture.applicationType}**`,
    `- Tech stack: ${architecture.techStack.languages.join(", ") || "unknown"} (${architecture.techStack.frameworks.join(", ") || "no framework"})`,
    `- **Confirmed: ${doc.confirmed.length}** · Needs validation: ${doc.needs_validation.length} · Rejected: ${doc.rejected.length}`,
    `- Coverage: ${covered}/${total} units covered, ${gaps} gaps detected`,
    `- Baseline comparable: ${architecture.comparableBaseline}`,
    ``,
    `## Coverage Ledger`,
    ``,
    ...renderLedgerTable(doc.coverage),
    ``,
    `## Confirmed Findings (${doc.confirmed.length})`,
    ``,
    ...doc.confirmed
      .slice()
      .sort((a, b) => (severityOrder[a.riskLevel] ?? 9) - (severityOrder[b.riskLevel] ?? 9))
      .map((r) => renderRecordSummary(r)),
    ``,
    `## Coverage Gaps (${gaps})`,
    ``,
    ...(doc.coverage.units
      .filter((u) => u.status === "gap-detected")
      .map((u) => `- **${u.name}** — ${u.description}`)
      .length > 0
      ? doc.coverage.units
          .filter((u) => u.status === "gap-detected")
          .map((u) => `- **${u.name}** — ${u.description}`)
      : ["- None"]),
    ``,
    `## Scan Limitations`,
    ``,
    `- Static analysis only: no execution of target code, no network probing.`,
    `- Units marked "gap-detected" may contain unverified vulnerabilities.`,
    `- "Needs validation" findings have an exact unresolved fact but no committed severity.`,
    ``,
    `See \`FINDINGS-DETAIL.md\` for data-flow detail and \`NEEDS-VALIDATION.md\` for the open fact list.`
  ].join("\n");

  return {
    reportMd,
    findingsDetailMd: buildFindingsDetail(doc, architecture),
    needsValidationMd: buildNeedsValidation(doc)
  };
}

function renderLedgerTable(coverage: CoverageLedger): string[] {
  const rows = coverage.units.map((u) => {
    const statusIcon = u.status === "covered" ? "✔" : u.status === "in-progress" ? "…" : "✘";
    return `| ${statusIcon} | \`${u.id}\` | ${u.name} | ${u.status} | ${u.findings.length} | ${u.assignedHunter ?? "-"} |`;
  });
  return [
    `| Status | Unit | Name | Status Label | Findings | Hunter |`,
    `|---|---|---|---|---|---|`,
    ...rows
  ];
}

function renderRecordSummary(record: FindingRecord): string {
  return [
    `### ${record.id} — ${record.category} (${record.riskLevel})`,
    ``,
    `- Location: \`${record.filePath}:${record.lineStart}\``,
    `- Tags: ${record.evidenceTags.join(", ")}`,
    `- Attack vector: ${record.attackVector ?? "n/a"}`,
    `- Explanation: ${record.explanation}`,
    `- Fix: ${record.recommendedFix}`
  ].join("\n");
}

function buildFindingsDetail(doc: FindingsDocument, architecture: ArchitectureSummary): string {
  const detailed = [...doc.confirmed, ...doc.needs_validation].filter(
    (r) => (severityOrder[r.riskLevel] ?? 9) <= 2
  );

  return [
    `# Findings Detail`,
    ``,
    `Detailed data-flow for MEDIUM+ findings. Target: \`${doc.target}\` · Generated ${doc.generatedAt}.`,
    ``,
    `Trust model baseline: ${architecture.trustModel.trustBoundaries.map((b) => b.name).join(", ") || "none identified"}.`,
    ``,
    ...detailed.map((record) => {
      const lines = [
        `## ${record.id} — ${record.category} (${record.riskLevel}, verdict: ${record.verdict})`,
        ``,
        `### Source → Sink`,
        ``,
        `- Source: \`${record.source ?? "unresolved"}\``,
        `- Sink: \`${record.sink ?? "unresolved"}\``,
        ``,
        `### Code`,
        ``,
        "```",
        record.codeSnippet,
        "```",
        ``,
        `### Verification`,
        ``,
        ...record.verification.checksPerformed.map((c) => `- [x] ${c}`),
        ``,
        `Evidence for: ${record.verification.evidenceFor.join("; ") || "none recorded"}`,
        `Evidence against: ${record.verification.evidenceAgainst.join("; ") || "none recorded"}`,
        ``,
        `Conclusion: ${record.verification.conclusion}`,
        ``,
        `### Validation Chain`,
        ``,
        ...record.validationChain.map(
          (v) => `- ${v.validatorId}: ${v.verdict} @ ${v.at}`
        ),
        ``
      ];
      return lines.join("\n");
    }),
    detailed.length === 0 ? "No MEDIUM+ findings to detail." : ""
  ].join("\n");
}

function buildNeedsValidation(doc: FindingsDocument): string {
  return [
    `# Needs Validation`,
    ``,
    `Findings with an exact unresolved fact and no committed severity. ${doc.needs_validation.length} item(s).`,
    ``,
    ...doc.needs_validation.map((record) =>
      [
        `## ${record.id} — ${record.category}`,
        ``,
        `- Location: \`${record.filePath}:${record.lineStart}\``,
        `- Unresolved fact: ${record.verification.conclusion}`,
        `- Evidence for: ${record.verification.evidenceFor.join("; ") || "none"}`,
        `- Evidence against: ${record.verification.evidenceAgainst.join("; ") || "none"}`,
        `- Recommended fix (if confirmed): ${record.recommendedFix}`,
        ``
      ].join("\n")
    ),
    doc.needs_validation.length === 0 ? "None." : ""
  ].join("\n");
}

export async function writeReportBundle(bundle: ReportBundle, outDir: string): Promise<string[]> {
  const fs = await import("node:fs/promises");
  const path = await import("node:path");
  await fs.mkdir(outDir, { recursive: true });
  const written: string[] = [];
  const files = [
    ["REPORT.md", bundle.reportMd],
    ["FINDINGS-DETAIL.md", bundle.findingsDetailMd],
    ["NEEDS-VALIDATION.md", bundle.needsValidationMd]
  ] as const;
  for (const [name, content] of files) {
    const file = path.join(outDir, name);
    await fs.writeFile(file, content);
    written.push(file);
  }
  return written;
}
