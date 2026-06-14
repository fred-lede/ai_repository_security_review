export const scannerCoreVersion = "0.1.0";
export {
  assertNoSymlinkArchiveEntry,
  assertRegularArchiveEntry,
  assertSafeArchiveEntry,
  isSupportedArchive
} from "./safeArchive.js";
export { buildInventory } from "./inventory.js";
export { buildDataFlowGraph } from "./dataFlow.js";
export {
  renderDecisionRecord,
  renderJsonReport,
  renderMarkdownReport,
  renderMermaidDataFlow,
  renderRemediationList,
  renderSarifReport
} from "./reporters.js";
export { applyBuiltinRules, builtinRules, generateFinding } from "./defaultRules.js";
export type { BuiltinRule } from "./defaultRules.js";
export { assessRisk } from "./risk.js";
export { compileRule, runRules } from "./rules.js";
export type { RuleDefinition, RuleMatchCondition, RuleHandler } from "./ruleTypes.js";
export { loadExternalRules, saveExternalRules } from "./ruleLoader.js";
export { acquireRemoteTarget, cleanupRemoteDir } from "./remoteAcquisition.js";
export { scanTarget } from "./scan.js";
export type { ScanOutputName, ScanResult } from "./scan.js";
export { resolveTarget } from "./targetResolver.js";
export type { DependencySource, NetworkEndpoint, PackageScript, ProjectInventory } from "./inventory.js";
export type { ArchiveEntryType } from "./safeArchive.js";
export type {
  AuditReport,
  Confidence,
  DataFlowEdge,
  DataFlowGraph,
  DataFlowNode,
  Decision,
  Finding,
  FindingCategory,
  Language,
  NetworkPolicy,
  OutputFormat,
  Remediation,
  ResolvedTarget,
  ReviewMode,
  RiskAssessment,
  RiskLevel,
  ScanOptions,
  TargetType
} from "./types.js";
