import fs from "node:fs/promises";
import path from "node:path";
import { listScannableFiles } from "./fileWalker.js";

export interface PackageScript {
  name: string;
  command: string;
  filePath: string;
}

export interface DependencySource {
  source: string;
  filePath: string;
}

export interface NetworkEndpoint {
  endpoint: string;
  filePath: string;
  line: number;
  snippet: string;
}

export interface ProjectInventory {
  files: string[];
  packageScripts: PackageScript[];
  dependencySources: DependencySource[];
  environmentVariables: string[];
  networkEndpoints: NetworkEndpoint[];
  commandExecutions: Array<{ filePath: string; line: number; snippet: string }>;
  filesystemReads: Array<{ filePath: string; line: number; snippet: string }>;
  githubWorkflowFiles: string[];
  electronIpcFiles: string[];
  persistenceIndicators: Array<{ filePath: string; line: number; snippet: string }>;
  dangerousCalls: DangerousCall[];
}

export type LanguageId = "python" | "javascript" | "go" | "java" | "shell" | "dockerfile" | "yaml";

export interface DangerousCall {
  filePath: string;
  line: number;
  snippet: string;
  language: LanguageId;
  pattern: string;
  evidenceTags: string[];
}

export interface LanguagePattern {
  id: string;
  regex: RegExp;
  tags: string[];
}

export const LANGUAGE_PATTERNS: Record<LanguageId, LanguagePattern[]> = {
  python: [
    {
      id: "python.subprocess",
      regex: /\b(?:subprocess\.(?:run|call|Popen|check_output|check_call)|os\.system|os\.popen)\s*\(/,
      tags: ["rce-candidate", "python", "command-execution"]
    },
    {
      id: "python.os_system",
      regex: /\bos\.system\s*\(/,
      tags: ["rce-candidate", "python", "command-execution"]
    },
    {
      id: "python.eval",
      regex: /(?:^|[^\w.])(?:eval|exec)\s*\(/,
      tags: ["rce-candidate", "python", "code-injection"]
    }
  ],
  javascript: [
    {
      id: "javascript.child_process",
      regex: /child_process\.(?:exec|execSync|spawn|spawnSync|fork)\s*\(|require\(["']child_process["']\)/,
      tags: ["rce-candidate", "javascript", "command-execution"]
    },
    {
      id: "javascript.eval",
      regex: /(?:^|[^\w.])eval\s*\(|new\s+Function\s*\(/,
      tags: ["rce-candidate", "javascript", "code-injection"]
    }
  ],
  go: [
    {
      id: "go.exec",
      regex: /(?:exec\.Command|os\.StartProcess|syscall\.Exec)\s*\(/,
      tags: ["rce-candidate", "go", "command-execution"]
    }
  ],
  java: [
    {
      id: "java.runtime_exec",
      regex: /Runtime\.getRuntime\(\)\.exec\s*\(/,
      tags: ["rce-candidate", "java", "command-execution"]
    },
    {
      id: "java.process_builder",
      regex: /new\s+ProcessBuilder\s*\(/,
      tags: ["rce-candidate", "java", "command-execution"]
    },
    {
      id: "java.jndi",
      regex: /new\s+InitialContext\s*\(/,
      tags: ["rce-candidate", "java", "jndi-injection"]
    }
  ],
  shell: [
    {
      id: "shell.curl_sh",
      regex: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sh|bash)\b/,
      tags: ["supply-chain", "shell", "remote-execution"]
    },
    {
      id: "shell.eval",
      regex: /(?:^|\s)eval\s+/,
      tags: ["rce-candidate", "shell", "code-injection"]
    },
    {
      id: "shell.base64_sh",
      regex: /base64\s+(-d|--decode)[^\n|]*\|\s*(?:sh|bash)\b/,
      tags: ["obfuscation", "shell", "remote-execution"]
    }
  ],
  dockerfile: [
    {
      id: "dockerfile.add_remote",
      regex: /^\s*ADD\s+(?:https?:\/\/)/i,
      tags: ["supply-chain", "dockerfile", "remote-download"]
    },
    {
      id: "dockerfile.curl_sh",
      regex: /RUN\s+[^\n]*(?:curl|wget)[^\n]*\|\s*(?:sh|bash)\b/i,
      tags: ["supply-chain", "dockerfile", "remote-execution"]
    },
    {
      id: "dockerfile.hardcoded_secret",
      regex: /(?:API_KEY|TOKEN|PASSWORD|SECRET)=["']?[A-Za-z0-9_\/+\-=]{8,}/i,
      tags: ["credential-leakage", "dockerfile"]
    }
  ],
  yaml: [
    {
      id: "yaml.pull_request_target",
      regex: /pull_request_target/,
      tags: ["supply-chain", "github-actions"]
    },
    {
      id: "yaml.external_action",
      regex: /uses:\s+[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@/,
      tags: ["supply-chain", "github-actions"]
    },
    {
      id: "yaml.self_hosted",
      regex: /runs-on:\s*["']?self-hosted["']?/,
      tags: ["github-actions", "self-hosted-runner"]
    },
    {
      id: "yaml.hardcoded_secret",
      regex: /(?:API_KEY|TOKEN|PASSWORD|SECRET):\s*["']?[A-Za-z0-9_\/+\-=]{8,}/i,
      tags: ["credential-leakage"]
    }
  ]
};

export async function buildInventory(targetPath: string): Promise<ProjectInventory> {
  const stat = await fs.stat(targetPath);
  const rootDir = stat.isFile() ? path.dirname(targetPath) : targetPath;
  const files = stat.isFile() ? [path.basename(targetPath)] : await listScannableFiles(rootDir);
  const inventory: ProjectInventory = {
    files,
    packageScripts: [],
    dependencySources: [],
    environmentVariables: [],
    networkEndpoints: [],
    commandExecutions: [],
    filesystemReads: [],
    githubWorkflowFiles: [],
    electronIpcFiles: [],
    persistenceIndicators: [],
    dangerousCalls: []
  };

  for (const filePath of files) {
    const fullPath = path.join(rootDir, filePath);
    const content = await fs.readFile(fullPath, "utf8").catch(() => "");

    if (path.basename(filePath) === "package.json") {
      collectPackageJson(content, filePath, inventory);
    }

    if (filePath.startsWith(".github/workflows/")) {
      inventory.githubWorkflowFiles.push(filePath);
    }

    collectRegex(content, /process\.env\.([A-Z0-9_]+)/g, (match) => inventory.environmentVariables.push(match[1]));
    collectRegex(content, /process\.env\[['"]([A-Z0-9_]+)['"]\]/g, (match) => inventory.environmentVariables.push(match[1]));
    collectNetworkEndpoints(content, filePath, inventory.networkEndpoints);
    collectLineMatches(
      content,
      filePath,
      /((?:^|[^.\w])(?:exec|spawn|execFile)\s*\(|curl\s+.*\|\s*bash)/,
      inventory.commandExecutions
    );
    collectLineMatches(
      content,
      filePath,
      /(?:\bfs\.)?(?:readFileSync|readFile|createReadStream)\s*\(/,
      inventory.filesystemReads
    );
    collectLineMatches(content, filePath, /(LaunchAgent|systemd|crontab|Startup|RunOnce|pm2|daemon)/i, inventory.persistenceIndicators);

    if (/ipcMain\.(handle|on)|contextBridge|nodeIntegration|contextIsolation/.test(content)) {
      inventory.electronIpcFiles.push(filePath);
    }

    collectDangerousCalls(content, filePath, inventory);
  }

  inventory.environmentVariables = unique(inventory.environmentVariables);
  inventory.networkEndpoints = uniqueNetworkEndpoints(inventory.networkEndpoints);
  inventory.dependencySources = uniqueDependencySources(inventory.dependencySources);
  inventory.dangerousCalls = uniqueDangerousCalls(inventory.dangerousCalls);

  return inventory;
}

function collectPackageJson(content: string, filePath: string, inventory: ProjectInventory): void {
  let parsed: unknown;

  try {
    parsed = JSON.parse(content);
  } catch {
    return;
  }

  if (!isRecord(parsed)) {
    return;
  }

  const scripts = parsed.scripts;
  if (isRecord(scripts)) {
    for (const [name, command] of Object.entries(scripts)) {
      if (typeof command === "string") {
        inventory.packageScripts.push({ name, command, filePath });
      }
    }
  }

  for (const deps of [
    parsed.dependencies,
    parsed.devDependencies,
    parsed.optionalDependencies,
    parsed.peerDependencies,
    parsed.bundledDependencies,
    parsed.bundleDependencies
  ]) {
    if (!isRecord(deps)) {
      continue;
    }

    for (const source of Object.values(deps)) {
      if (typeof source !== "string") {
        continue;
      }

      if (isSuspiciousDependencySource(source)) {
        inventory.dependencySources.push({ source, filePath });
      }
    }
  }
}

function collectRegex(content: string, regex: RegExp, onMatch: (match: RegExpExecArray) => void): void {
  for (let match = regex.exec(content); match; match = regex.exec(content)) {
    onMatch(match);
  }
}

function collectNetworkEndpoints(content: string, filePath: string, output: NetworkEndpoint[]): void {
  if (isLockfile(filePath)) {
    return;
  }

  content.split(/\r?\n/).forEach((lineText, index) => {
    for (const endpoint of lineText.matchAll(/https?:\/\/[^\s"'`)]+/g)) {
      output.push({
        endpoint: endpoint[0],
        filePath,
        line: index + 1,
        snippet: lineText.trim()
      });
    }
  });
}

function isLockfile(filePath: string): boolean {
  return /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock)$/.test(filePath);
}

function collectLineMatches(
  content: string,
  filePath: string,
  regex: RegExp,
  output: Array<{ filePath: string; line: number; snippet: string }>
): void {
  content.split(/\r?\n/).forEach((lineText, index) => {
    if (regex.test(lineText)) {
      output.push({ filePath, line: index + 1, snippet: lineText.trim() });
    }
  });
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values)).sort();
}

function uniqueNetworkEndpoints(values: NetworkEndpoint[]): NetworkEndpoint[] {
  return Array.from(
    new Map(values.map((value) => [`${value.filePath}\0${value.line}\0${value.endpoint}\0${value.snippet}`, value])).values()
  ).sort((a, b) => {
    const filePathOrder = a.filePath.localeCompare(b.filePath);
    if (filePathOrder !== 0) {
      return filePathOrder;
    }

    const lineOrder = a.line - b.line;
    return lineOrder === 0 ? a.endpoint.localeCompare(b.endpoint) : lineOrder;
  });
}

function uniqueDependencySources(values: DependencySource[]): DependencySource[] {
  return Array.from(new Map(values.map((value) => [`${value.filePath}\0${value.source}`, value])).values()).sort((a, b) => {
    const filePathOrder = a.filePath.localeCompare(b.filePath);
    return filePathOrder === 0 ? a.source.localeCompare(b.source) : filePathOrder;
  });
}

function detectLanguage(filePath: string, content: string): LanguageId | undefined {
  const lower = filePath.toLowerCase();
  if (lower.endsWith(".py")) return "python";
  if (/\.(js|jsx|ts|tsx|mjs|cjs)$/.test(lower)) return "javascript";
  if (lower.endsWith(".go")) return "go";
  if (lower.endsWith(".java")) return "java";
  if (/\.(sh|bash|zsh)$/.test(lower) || content.startsWith("#!")) return "shell";
  if (path.basename(filePath) === "Dockerfile" || /\.dockerfile$/.test(lower)) return "dockerfile";
  if (/\.(ya?ml)$/.test(lower)) return "yaml";
  return undefined;
}

function collectDangerousCalls(
  content: string,
  filePath: string,
  inventory: ProjectInventory
): void {
  const lang = detectLanguage(filePath, content);
  if (!lang) {
    return;
  }

  const patterns = LANGUAGE_PATTERNS[lang];
  content.split(/\r?\n/).forEach((lineText, index) => {
    for (const pattern of patterns) {
      if (pattern.regex.test(lineText)) {
        inventory.dangerousCalls.push({
          filePath,
          line: index + 1,
          snippet: lineText.trim(),
          language: lang,
          pattern: pattern.id,
          evidenceTags: pattern.tags
        });
      }
    }
  });
}

function uniqueDangerousCalls(values: DangerousCall[]): DangerousCall[] {
  return Array.from(
    new Map(values.map((value) => [`${value.filePath}\0${value.line}\0${value.pattern}`, value])).values()
  ).sort((a, b) => {
    const filePathOrder = a.filePath.localeCompare(b.filePath);
    if (filePathOrder !== 0) return filePathOrder;
    const lineOrder = a.line - b.line;
    return lineOrder === 0 ? a.pattern.localeCompare(b.pattern) : lineOrder;
  });
}

function isSuspiciousDependencySource(source: string): boolean {
  return (
    source.startsWith("github:") ||
    source.startsWith("git+") ||
    source.startsWith("git://") ||
    source.startsWith("ssh://") ||
    source.startsWith("http://") ||
    source.startsWith("https://") ||
    source.startsWith("file:") ||
    /^git@[^:]+:.+/.test(source)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
