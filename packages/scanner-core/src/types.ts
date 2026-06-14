export type TargetType =
  | "local-directory"
  | "local-file"
  | "archive"
  | "github"
  | "npm-package"
  | "npm-tarball"
  | "remote-archive";

export type ReviewMode = "quick-triage" | "full-audit" | "ci-gate";
export type NetworkPolicy = "online" | "no-network" | "offline";
export type RiskLevel = "Critical" | "High" | "Medium" | "Low" | "Info";
export type Confidence = "High" | "Medium" | "Low";
export type Decision = "Block" | "Needs Review" | "Monitor" | "Pass";

export interface ScanOptions {
  reviewMode: ReviewMode;
  networkPolicy: NetworkPolicy;
  outputFormats: Array<"markdown" | "json" | "sarif" | "mermaid">;
}

export interface ResolvedTarget {
  type: TargetType;
  source: string;
  localPath: string;
  provenance: Record<string, string | boolean | number>;
  networkUsed: boolean;
  trustBoundary: "local" | "remote" | "archive";
}

export interface Finding {
  id: string;
  riskLevel: RiskLevel;
  category:
    | "data-exfiltration"
    | "credential-leakage"
    | "hidden-telemetry"
    | "tracking"
    | "remote-code-execution"
    | "command-injection"
    | "supply-chain"
    | "postinstall-script"
    | "github-actions"
    | "electron-ipc"
    | "persistence"
    | "network"
    | "filesystem"
    | "environment"
    | "database";
  filePath: string;
  lineStart: number;
  lineEnd: number;
  codeSnippet: string;
  explanation: string;
  recommendedFix: string;
  evidenceTags: string[];
  source?: string;
  sink?: string;
  dataFlowId?: string;
  confidence: Confidence;
  remediation?: Remediation;
}

export interface Remediation {
  summary: string;
  saferPattern: string;
  testSuggestion: string;
  breakingChangeRisk: "High" | "Medium" | "Low";
  patchDraft?: string;
}

export interface DataFlowNode {
  id: string;
  label: string;
  kind: "source" | "process" | "local-sink" | "external-destination" | "ai-provider";
  leavesMachine: boolean;
}

export interface DataFlowEdge {
  id: string;
  from: string;
  to: string;
  label: string;
  findingIds: string[];
}

export interface DataFlowGraph {
  nodes: DataFlowNode[];
  edges: DataFlowEdge[];
}

export interface RiskAssessment {
  overallRiskLevel: RiskLevel;
  decision: Decision;
  rationale: string;
  topRisks: string[];
  severityCounts: Record<RiskLevel, number>;
  categoryCounts: Record<string, number>;
  blockingFindingIds: string[];
  residualRisk: string;
  scanLimitations: string[];
}

export interface AuditReport {
  target: ResolvedTarget;
  findings: Finding[];
  dataFlow: DataFlowGraph;
  risk: RiskAssessment;
  generatedAt: string;
  toolVersion: string;
}
