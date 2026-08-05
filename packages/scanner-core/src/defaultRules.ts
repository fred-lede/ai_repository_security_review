import type { ProjectInventory } from "./inventory.js";
import type { Finding, FindingCategory, RiskLevel } from "./types.js";
import { compileRule, type RuleDefinition, type RuleHandler } from "./ruleTypes.js";
import { matchesGlob } from "./glob.js";

type RiskLevelFn = (item: Record<string, unknown>, inventory: ProjectInventory) => RiskLevel;
type ExplanationFn = (item: Record<string, unknown>, inventory: ProjectInventory) => string;
type FixFn = (item: Record<string, unknown>) => string;
type TagsFn = (item: Record<string, unknown>, inventory: ProjectInventory) => string[];
type SnippetFn = (item: Record<string, unknown>) => string;
type DangerousCallTagsFn = (item: Record<string, unknown>) => string[];

const dcTags: DangerousCallTagsFn = (item) => {
  const tags = item.evidenceTags;
  return Array.isArray(tags) ? (tags as string[]) : [];
};

export interface BuiltinRule {
  id: string;
  description: string;
  category: FindingCategory;
  defaultRiskLevel: RiskLevel;
  inventoryField: string;
  pathPattern?: string;
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
  },
  {
    id: "python-subprocess-exec",
    description: "Detects Python subprocess or OS shell execution",
    category: "command-injection",
    defaultRiskLevel: "High",
    inventoryField: "dangerousCalls",
    pathPattern: "**/*.py",
    match: (item) => ["python.subprocess", "python.os_system"].includes(String(item.pattern)),
    riskLevel: () => "High",
    snippet: (item) => String(item.snippet),
    explanation: () =>
      "Python invokes subprocess or OS shell execution. If input reaches this call it can become command injection or RCE.",
    recommendedFix: () =>
      "Avoid shell execution. Use Python stdlib subprocess with explicit argument lists and no shell=True.",
    tags: dcTags
  },
  {
    id: "python-eval",
    description: "Detects Python eval/exec code injection",
    category: "remote-code-execution",
    defaultRiskLevel: "High",
    inventoryField: "dangerousCalls",
    pathPattern: "**/*.py",
    match: (item) => String(item.pattern) === "python.eval",
    riskLevel: () => "High",
    snippet: (item) => String(item.snippet),
    explanation: () =>
      "Python evaluates dynamically constructed code. Untrusted input reaching eval/exec enables arbitrary code execution.",
    recommendedFix: () =>
      "Remove eval/exec or use AST parsing when you must interpret dynamic code.",
    tags: dcTags
  },
  {
    id: "js-child-process",
    description: "Detects Node.js child process execution",
    category: "command-injection",
    defaultRiskLevel: "High",
    inventoryField: "dangerousCalls",
    pathPattern: "**/*.{js,jsx,ts,tsx,mjs,cjs}",
    match: (item) => String(item.pattern) === "javascript.child_process",
    riskLevel: () => "High",
    snippet: (item) => String(item.snippet),
    explanation: () =>
      "Node.js spawns a child process. User-controlled input reaching exec/spawn can become command injection or RCE.",
    recommendedFix: () =>
      "Use execFile/spawn with explicit argument arrays and strict input validation instead of shell strings.",
    tags: dcTags
  },
  {
    id: "js-eval",
    description: "Detects JavaScript eval / new Function code injection",
    category: "remote-code-execution",
    defaultRiskLevel: "High",
    inventoryField: "dangerousCalls",
    pathPattern: "**/*.{js,jsx,ts,tsx,mjs,cjs}",
    match: (item) => String(item.pattern) === "javascript.eval",
    riskLevel: () => "High",
    snippet: (item) => String(item.snippet),
    explanation: () =>
      "JavaScript dynamically evaluates code. Untrusted input reaching eval or new Function enables arbitrary code execution.",
    recommendedFix: () =>
      "Remove eval/new Function. Prefer data-driven JSON parsing or a sandboxed evaluator.",
    tags: dcTags
  },
  {
    id: "go-exec-command",
    description: "Detects Go command execution",
    category: "command-injection",
    defaultRiskLevel: "High",
    inventoryField: "dangerousCalls",
    pathPattern: "**/*.go",
    match: (item) => String(item.pattern) === "go.exec",
    riskLevel: () => "High",
    snippet: (item) => String(item.snippet),
    explanation: () =>
      "Go executes an external command. Shell-interpreted input reaching exec.Command can become command injection.",
    recommendedFix: () =>
      "Avoid building shell strings. Pass arguments as a slice and validate inputs strictly.",
    tags: dcTags
  },
  {
    id: "java-runtime-exec",
    description: "Detects Java process execution",
    category: "command-injection",
    defaultRiskLevel: "Critical",
    inventoryField: "dangerousCalls",
    pathPattern: "**/*.java",
    match: (item) => ["java.runtime_exec", "java.process_builder"].includes(String(item.pattern)),
    riskLevel: () => "Critical",
    snippet: (item) => String(item.snippet),
    explanation: () =>
      "Java launches an external process. Untrusted input reaching Runtime.exec or ProcessBuilder can enable RCE.",
    recommendedFix: () =>
      "Prefer safe APIs and pass arguments as an array (ProcessBuilder) without shell interpretation.",
    tags: dcTags
  },
  {
    id: "java-jndi",
    description: "Detects Java JNDI lookup (Log4Shell-style vector)",
    category: "remote-code-execution",
    defaultRiskLevel: "Critical",
    inventoryField: "dangerousCalls",
    pathPattern: "**/*.java",
    match: (item) => String(item.pattern) === "java.jndi",
    riskLevel: () => "Critical",
    snippet: (item) => String(item.snippet),
    explanation: () =>
      "Java performs a JNDI InitialContext lookup. An attacker-controlled JNDI URL can trigger remote class loading.",
    recommendedFix: () =>
      "Do not pass untrusted input to JNDI lookups. Restrict allowed JNDI protocols and disable remote codebases.",
    tags: dcTags
  },
  {
    id: "shell-pipe-to-sh",
    description: "Detects shell remote pipe-to-shell execution",
    category: "supply-chain",
    defaultRiskLevel: "Critical",
    inventoryField: "dangerousCalls",
    pathPattern: "**/*.{sh,bash,zsh}",
    match: (item) => String(item.pattern) === "shell.curl_sh",
    riskLevel: () => "Critical",
    snippet: (item) => String(item.snippet),
    explanation: () =>
      "Shell pipes a remote download directly into sh/bash. The remote script executes without review.",
    recommendedFix: () =>
      "Download the script, inspect it, and execute a pinned, reviewed artifact instead of piping to shell.",
    tags: dcTags
  },
  {
    id: "shell-eval",
    description: "Detects shell eval usage",
    category: "remote-code-execution",
    defaultRiskLevel: "High",
    inventoryField: "dangerousCalls",
    pathPattern: "**/*.{sh,bash,zsh}",
    match: (item) => String(item.pattern) === "shell.eval",
    riskLevel: () => "High",
    snippet: (item) => String(item.snippet),
    explanation: () =>
      "Shell evaluates dynamically constructed commands. Untrusted input reaching eval enables command injection.",
    recommendedFix: () =>
      "Avoid eval. Parse input explicitly and validate it before use.",
    tags: dcTags
  },
  {
    id: "shell-base64-obfuscation",
    description: "Detects base64-decoded shell execution",
    category: "remote-code-execution",
    defaultRiskLevel: "High",
    inventoryField: "dangerousCalls",
    pathPattern: "**/*.{sh,bash,zsh}",
    match: (item) => String(item.pattern) === "shell.base64_sh",
    riskLevel: () => "High",
    snippet: (item) => String(item.snippet),
    explanation: () =>
      "Shell decodes base64 and pipes it to sh/bash, hiding the executed payload from casual review.",
    recommendedFix: () =>
      "Replace obfuscated execution with an explicit, reviewed script.",
    tags: dcTags
  },
  {
    id: "dockerfile-add-remote",
    description: "Detects Dockerfile ADD of remote URLs",
    category: "supply-chain",
    defaultRiskLevel: "High",
    inventoryField: "dangerousCalls",
    pathPattern: "**/Dockerfile*",
    match: (item) => String(item.pattern) === "dockerfile.add_remote",
    riskLevel: () => "High",
    snippet: (item) => String(item.snippet),
    explanation: () =>
      "Dockerfile ADD fetches a remote archive with no integrity verification, enabling supply-chain tampering.",
    recommendedFix: () =>
      "Use COPY from a reviewed artifact and pin the source with a checksum.",
    tags: dcTags
  },
  {
    id: "dockerfile-run-pipe",
    description: "Detects Dockerfile RUN curl|sh",
    category: "supply-chain",
    defaultRiskLevel: "Critical",
    inventoryField: "dangerousCalls",
    pathPattern: "**/Dockerfile*",
    match: (item) => String(item.pattern) === "dockerfile.curl_sh",
    riskLevel: () => "Critical",
    snippet: (item) => String(item.snippet),
    explanation: () =>
      "Dockerfile RUN pipes a remote download into sh/bash during build, executing unreviewed code.",
    recommendedFix: () =>
      "Download, verify, and run a pinned artifact; never pipe remote content to a shell.",
    tags: dcTags
  },
  {
    id: "actions-pr-target",
    description: "Detects pull_request_target in GitHub Actions",
    category: "supply-chain",
    defaultRiskLevel: "High",
    inventoryField: "dangerousCalls",
    pathPattern: ".github/workflows/**",
    match: (item) => String(item.pattern) === "yaml.pull_request_target",
    riskLevel: () => "High",
    snippet: (item) => String(item.snippet),
    explanation: () =>
      "pull_request_target runs with repository secrets on untrusted fork code, enabling secret exfiltration.",
    recommendedFix: () =>
      "Avoid pull_request_target. If required, run it only for metadata and never check out fork code.",
    tags: dcTags
  },
  {
    id: "actions-external-action",
    description: "Detects third-party actions in GitHub workflows",
    category: "supply-chain",
    defaultRiskLevel: "Medium",
    inventoryField: "dangerousCalls",
    pathPattern: ".github/workflows/**",
    match: (item) => String(item.pattern) === "yaml.external_action",
    riskLevel: () => "Medium",
    snippet: (item) => String(item.snippet),
    explanation: () =>
      "The workflow references a third-party action. Pin to a full commit SHA and review it before use.",
    recommendedFix: () =>
      "Pin external actions to full commit SHAs and audit their source.",
    tags: dcTags
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
      if (rule.pathPattern && !matchesGlob(rule.pathPattern, String(item.filePath ?? ""))) {
        continue;
      }
      if (rule.match(item, inventory)) {
        findings.push(generateFinding(rule, item, inventory));
      }
    }
  }

  findings.push(...networkRule(inventory));

  return findings.map((item, index) => ({ ...item, id: `finding-${index + 1}` }));
}
