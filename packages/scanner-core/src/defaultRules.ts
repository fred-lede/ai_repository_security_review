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

const threatSignalTags: TagsFn = (item) => {
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
  },
  {
    id: "reverse-shell",
    description: "Detects reverse or bind shells that connect back to an attacker-controlled host",
    category: "network-attack",
    defaultRiskLevel: "Critical",
    inventoryField: "threatSignals",
    match: (item) => ["reverse-shell-dev-tcp", "reverse-shell-nc", "bind-shell"].includes(String(item.pattern)),
    riskLevel: () => "Critical" as RiskLevel,
    snippet: (item) => String(item.snippet),
    explanation: () =>
      "The code establishes a reverse or bind shell, granting an attacker interactive remote access to the machine.",
    recommendedFix: () => "Remove shell-backdoor code and terminate any active sessions; scan for how this code was introduced.",
    tags: threatSignalTags
  },
  {
    id: "ssrf-sink",
    description: "Detects server-side request forgery sinks where a variable reaches an HTTP client",
    category: "network-attack",
    defaultRiskLevel: "High",
    inventoryField: "threatSignals",
    match: (item) => String(item.pattern) === "ssrf-sink",
    riskLevel: () => "High" as RiskLevel,
    snippet: (item) => String(item.snippet),
    explanation: () =>
      "An HTTP client is called with a non-literal URL. If user-controlled, it becomes SSRF enabling access to internal resources.",
    recommendedFix: () => "Validate and allowlist destination URLs; never pass raw user input to HTTP clients.",
    tags: threatSignalTags
  },
  {
    id: "port-scan",
    description: "Detects port scanning primitives",
    category: "network-attack",
    defaultRiskLevel: "Medium",
    inventoryField: "threatSignals",
    match: (item) => String(item.pattern) === "port-scan",
    riskLevel: () => "Medium" as RiskLevel,
    snippet: (item) => String(item.snippet),
    explanation: () =>
      "The code performs network reconnaissance (connect_ex, nmap, or masscan). This may indicate scanning or lateral movement.",
    recommendedFix: () => "Remove scanning utilities unless this is an authorized security tool with documented scope.",
    tags: threatSignalTags
  },
  {
    id: "credential-harvest",
    description: "Detects client-side credential harvesting (password reads, storage/cookie access)",
    category: "phishing",
    defaultRiskLevel: "Critical",
    inventoryField: "threatSignals",
    match: (item) => String(item.pattern) === "credential-harvest",
    riskLevel: () => "Critical" as RiskLevel,
    snippet: (item) => String(item.snippet),
    explanation: () =>
      "The code reads password fields, localStorage, or cookies. When combined with outbound transmission this is credential harvesting.",
    recommendedFix: () => "Remove credential collection; if legitimate, keep credentials inside server-side sessions and never transmit them to third parties.",
    tags: threatSignalTags
  },
  {
    id: "keylogger",
    description: "Detects keyboard logging primitives",
    category: "phishing",
    defaultRiskLevel: "High",
    inventoryField: "threatSignals",
    match: (item) => String(item.pattern) === "keylogger",
    riskLevel: () => "High" as RiskLevel,
    snippet: (item) => String(item.snippet),
    explanation: () =>
      "The code registers keyboard listeners or hook APIs that capture keystrokes. This is characteristic of phishing/keylogging malware.",
    recommendedFix: () => "Remove keystroke capture unless it is an explicitly documented accessibility feature.",
    tags: threatSignalTags
  },
  {
    id: "exfiltration-sink",
    description: "Detects outbound data-exfiltration sinks (webhooks, encoded channels, non-HTTP, file upload)",
    category: "data-exfiltration",
    defaultRiskLevel: "High",
    inventoryField: "threatSignals",
    match: (item) => ["webhook-sink", "encoded-sink", "non-http-sink", "file-upload-sink"].includes(String(item.pattern)),
    riskLevel: () => "High" as RiskLevel,
    snippet: (item) => String(item.snippet),
    explanation: () =>
      "The code sends data through an exfiltration channel (webhook, encoded stream, non-HTTP connection, or file upload).",
    recommendedFix: () => "Remove unauthorized outbound channels and route data only through approved, audited endpoints.",
    tags: threatSignalTags
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

export function exfiltrationCorrelation(
  inventory: ProjectInventory,
  existing: Finding[]
): Finding[] {
  const sinkPatterns = new Set(["webhook-sink", "encoded-sink", "non-http-sink", "file-upload-sink"]);
  const hasSensitiveSource =
    inventory.environmentVariables.length > 0 ||
    inventory.filesystemReads.length > 0 ||
    inventory.commandExecutions.length > 0;
  const newFindings: Finding[] = [];

  if (!hasSensitiveSource) {
    return newFindings;
  }

  for (const signal of inventory.threatSignals) {
    if (!sinkPatterns.has(signal.pattern)) {
      continue;
    }

    const alreadyExfil = existing.find(
      (f) =>
        f.category === "data-exfiltration" &&
        f.filePath === signal.filePath &&
        f.lineStart === signal.line
    );
    if (alreadyExfil) {
      alreadyExfil.evidenceTags = Array.from(
        new Set([...alreadyExfil.evidenceTags, "exfiltration-candidate"])
      );
      continue;
    }

    newFindings.push({
      id: "",
      category: "data-exfiltration",
      riskLevel: "High",
      filePath: signal.filePath,
      lineStart: signal.line,
      lineEnd: signal.line,
      codeSnippet: signal.snippet,
      explanation:
        "The project contains sensitive sources (env vars, filesystem reads, or command execution) and an outbound exfiltration sink. This is an exfiltration candidate — review whether sensitive data can flow to this destination.",
      recommendedFix:
        "Remove unauthorized outbound channels or isolate sensitive data from network-accessible code.",
      evidenceTags: [...signal.evidenceTags, "exfiltration-candidate"],
      confidence: "High"
    });
  }

  return newFindings;
}

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
  findings.push(...exfiltrationCorrelation(inventory, findings));

  return findings.map((item, index) => ({ ...item, id: `finding-${index + 1}` }));
}
