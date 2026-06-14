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
}

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
    persistenceIndicators: []
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
    collectLineMatches(content, filePath, /(\b(?:exec|spawn|execFile)\s*\(|curl\s+.*\|\s*bash)/, inventory.commandExecutions);
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
  }

  inventory.environmentVariables = unique(inventory.environmentVariables);
  inventory.networkEndpoints = uniqueNetworkEndpoints(inventory.networkEndpoints);
  inventory.dependencySources = uniqueDependencySources(inventory.dependencySources);

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
