export const scannerCoreVersion = "0.1.0";
export {
  assertNoSymlinkArchiveEntry,
  assertRegularArchiveEntry,
  assertSafeArchiveEntry,
  isSupportedArchive
} from "./safeArchive.js";
export { buildInventory, buildScanCoverage, LANGUAGE_PATTERNS } from "./inventory.js";
export { listScannableFiles } from "./fileWalker.js";
export { matchesGlob } from "./glob.js";
export { buildDataFlowGraph } from "./dataFlow.js";
export {
  renderDecisionRecord,
  renderJsonReport,
  renderMarkdownReport,
  renderMermaidDataFlow,
  renderRemediationList,
  renderSarifReport,
  buildRiskMatrix,
  buildAttackSurface
} from "./reporters.js";
export type { RiskMatrixRow } from "./reporters.js";
export { applyBuiltinRules, builtinRules, exfiltrationCorrelation, generateFinding } from "./defaultRules.js";
export type { BuiltinRule } from "./defaultRules.js";
export { assessRisk } from "./risk.js";
export { computeFinalVerdict, computeTrustScore } from "./trustScore.js";
export type { TrustScore } from "./trustScore.js";
export { computeMetrics, computeMetricsFromCounts, matchFindings } from "./benchmark.js";
export type { BenchExpectation, BenchMatch, BenchMatchResult, BenchMetrics } from "./benchmark.js";
export { compileRule, runRules } from "./rules.js";
export type { RuleDefinition, RuleMatchCondition, RuleHandler } from "./ruleTypes.js";
export { loadExternalRules, saveExternalRules } from "./ruleLoader.js";
export { acquireRemoteTarget, cleanupRemoteDir } from "./remoteAcquisition.js";
export { renderOutputs, scanTarget } from "./scan.js";
export type { ScanOutputName, ScanResult } from "./scan.js";
export { resolveTarget } from "./targetResolver.js";
export {
  runFullAudit,
  validateCoverageLedger,
  attachAuditToReport,
  type AuditOptions,
  type AuditResult
} from "./audit.js";
export {
  runReconnaissance,
  updateCoverageLedger,
  findCoverageGaps,
  serializeCoverageLedger,
  deserializeCoverageLedger,
  type ArchitectureSummary,
  type CoverageLedger,
  type CoverageUnit,
  type TrustBoundary,
  type InputSurface
} from "./reconnaissance.js";
export {
  runHuntingPhase,
  runCoverageCritic,
  ATTACK_CLASS_PROMPTS,
  type AttackClassPrompt,
  type CandidateFinding,
  type HunterResult
} from "./hunting.js";
export {
  runValidationPhase,
  convertToFinding,
  filterConfirmed,
  filterNeedsValidation,
  filterRejected,
  type Verdict,
  type ValidatedFinding,
  type VerificationRecord,
  type ValidationResult
} from "./validation.js";
export {
  buildFindingsDocument,
  validateFindingsDocument,
  serializeFindingsDocument,
  deserializeFindingsDocument,
  mergePriorFindings,
  type FindingRecord,
  type FindingsDocument,
  type FindingsValidationResult
} from "./structuredOutput.js";
export {
  verifyFindingRecords,
  checkRecordClaims,
  isMaterialReplacement,
  type IndependentVerificationResult,
  type VerificationOutcome
} from "./independentVerification.js";
export {
  buildReportBundle,
  writeReportBundle,
  type ReportBundle
} from "./targetNeutralReporting.js";
export type { DangerousCall, DependencySource, LanguageId, LanguagePattern, NetworkEndpoint, PackageScript, ProjectInventory } from "./inventory.js";
export type { ArchiveEntryType } from "./safeArchive.js";
export type {
  AttackSurfaceEntry,
  AuditReport,
  Confidence,
  DataFlowEdge,
  DataFlowGraph,
  DataFlowNode,
  Decision,
  Finding,
  FindingCategory,
  Language,
  LanguageCoverage,
  NetworkPolicy,
  OutputFormat,
  Remediation,
  ResolvedTarget,
  ReviewMode,
  RiskAssessment,
  RiskLevel,
  ScanCoverage,
  ScanOptions,
  TargetType,
  ThreatFamily,
  ThreatSignal
} from "./types.js";
