import type { ProjectInventory } from "./inventory.js";
import type { Finding, FindingCategory, RiskLevel } from "./types.js";
import { compileRule, type RuleDefinition, type RuleHandler } from "./ruleTypes.js";

type RiskLevelFn = (item: Record<string, unknown>, inventory: ProjectInventory) => RiskLevel;
type ExplanationFn = (item: Record<string, unknown>, inventory: ProjectInventory) => string;
type FixFn = (item: Record<string, unknown>) => string;
type TagsFn = (item: Record<string, unknown>, inventory: ProjectInventory) => string[];
type SnippetFn = (item: Record<string, unknown>) => string;

export interface BuiltinRule {
  id: string;
  description: string;
  category: FindingCategory;
  defaultRiskLevel: RiskLevel;
  inventoryField: string;
  riskLevel: RiskLevelFn;
  match: (item: Record<string, unknown>, inventory: ProjectInventory) => boolean;
  explanation: ExplanationFn;
  recommendedFix: FixFn;
  tags: TagsFn;
  snippet?: SnippetFn;
}

const lifecycleScripts = ["preinstall", "install", "postinstall", "prepare", "prepack", "postpack"];

export const builtinRules: BuiltinRule[] = [
  {
    id: "postinstall-script",
    description: "Detects lifecycle scripts that run during package installation",
    category: "postinstall-script",
    defaultRiskLevel: "High",
    inventoryField: "packageScripts",
    match: (item) => lifecycleScripts.includes(String(item.name)),
    riskLevel: () => "High" as RiskLevel,
    snippet: (item) => `"${item.name}": "${item.command}"`,
    explanation: (item) =>
      `The package defines a ${item.name} lifecycle script. Lifecycle scripts run during installation and can execute code before review.`,
    recommendedFix: () =>
      "Remove install-time side effects or move setup behind an explicit user command.",
    tags: (item) => ["package-script", String(item.name)]
  },
  {
    id: "unpinned-dependency",
    description: "Detects dependencies using unpinned sources (git, HTTP, tarball, local file)",
    category: "supply-chain",
    defaultRiskLevel: "High",
    inventoryField: "dependencySources",
    match: () => true,
    riskLevel: (item) => String(item.source).startsWith("file:") ? "Medium" : "High",
    explanation: () =>
      "Dependency source uses git, HTTP, tarball, or local file resolution rather than a pinned registry version.",
    recommendedFix: () =>
      "Replace with a pinned registry version and verify the lockfile integrity.",
    tags: () => ["dependency-source"]
  },
  {
    id: "command-execution",
    description: "Detects shell or process execution that could lead to command injection",
    category: "command-injection",
    defaultRiskLevel: "High",
    inventoryField: "commandExecutions",
    match: () => true,
    riskLevel: (item) => String(item.snippet).includes("| bash") ? "Critical" : "High",
    explanation: () =>
      "The code invokes shell or process execution. If user-controlled data reaches this call, it can become command injection or RCE.",
    recommendedFix: () =>
      "Avoid shell execution. Use safe APIs with explicit argument arrays and strict input validation.",
    tags: () => ["command-execution"]
  }
];

function isTestOrExampleFile(filePath: string): boolean {
  return /(?:^|\/)(?:tests?|__tests__|fixtures?|examples?)\//i.test(filePath) ||
    /\.(?:test|spec)\.[cm]?[jt]sx?$/i.test(filePath);
}

function isExampleEndpoint(endpoint: string): boolean {
  return /^https?:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?(?:\/|$)/.test(endpoint) ||
    /\.example(?:\.com|\.org|\.test)(?:[:/]|$)/.test(endpoint);
}

export const networkRule: RuleHandler = (inventory) => {
  const findings: Finding[] = [];

  for (const endpoint of inventory.networkEndpoints) {
    const testOrExample = isTestOrExampleFile(endpoint.filePath) || isExampleEndpoint(endpoint.endpoint);
    const hasSensitiveSource =
      !testOrExample &&
      (endpoint.snippet.includes("process.env") ||
        inventory.filesystemReads.some((read) => read.filePath === endpoint.filePath) ||
        inventory.commandExecutions.some((cmd) => cmd.filePath === endpoint.filePath));

    findings.push({
      id: "",
      category: "network",
      riskLevel: testOrExample ? "Low" : hasSensitiveSource ? "High" : "Medium",
      filePath: endpoint.filePath,
      lineStart: endpoint.line,
      lineEnd: endpoint.line,
      codeSnippet: endpoint.snippet,
      explanation: testOrExample
        ? "The project references an endpoint in a test, fixture, localhost, or example context. Confirm it cannot be used by production code."
        : hasSensitiveSource
          ? "The project contains outbound network communication near sensitive local sources or process execution, making this an exfiltration candidate. Review whether sensitive data can flow to this destination."
          : "The project communicates with an external endpoint. Confirm this behavior is expected.",
      recommendedFix: testOrExample
        ? "Keep test/example endpoints out of production configuration and ensure they cannot be selected at runtime."
        : "Document expected endpoints, minimize payloads, and require explicit consent before sending sensitive data.",
      evidenceTags: hasSensitiveSource
        ? ["network-endpoint", "exfiltration-candidate", "sensitive-source-present"]
        : testOrExample
          ? ["network-endpoint", "test-or-example-endpoint"]
          : ["network-endpoint"],
      sink: endpoint.endpoint,
      confidence: "High"
    });
  }

  return findings;
};

export function generateFinding(
  rule: BuiltinRule,
  item: Record<string, unknown>,
  inventory: ProjectInventory
): Finding {
  return {
    id: "",
    category: rule.category,
    riskLevel: rule.riskLevel(item, inventory),
    filePath: String(item.filePath ?? ""),
    lineStart: Number(item.line ?? item.lineStart ?? 1),
    lineEnd: Number(item.line ?? item.lineEnd ?? item.lineStart ?? 1),
    codeSnippet: rule.snippet
      ? rule.snippet(item)
      : String(item.snippet ?? item.command ?? item.source ?? item.name ?? ""),
    explanation: rule.explanation(item, inventory),
    recommendedFix: rule.recommendedFix(item),
    evidenceTags: rule.tags(item, inventory),
    confidence: rule.defaultRiskLevel === "Info" ? "Medium" : "High"
  };
}

function getItems(inventory: ProjectInventory, field: string): Record<string, unknown>[] {
  const data = (inventory as unknown as Record<string, unknown>)[field];
  return Array.isArray(data) ? data as Record<string, unknown>[] : [];
}

export function applyBuiltinRules(inventory: ProjectInventory): Finding[] {
  const findings: Finding[] = [];

  for (const rule of builtinRules) {
    const items = getItems(inventory, rule.inventoryField);
    for (const item of items) {
      if (rule.match(item, inventory)) {
        findings.push(generateFinding(rule, item, inventory));
      }
    }
  }

  findings.push(...networkRule(inventory));

  return findings.map((item, index) => ({ ...item, id: `finding-${index + 1}` }));
}
