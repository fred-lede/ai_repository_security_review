export const scannerCoreVersion = "0.1.0";
export {
  assertNoSymlinkArchiveEntry,
  assertRegularArchiveEntry,
  assertSafeArchiveEntry,
  isSupportedArchive
} from "./safeArchive.js";
export { buildInventory } from "./inventory.js";
export { runRules } from "./rules.js";
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
