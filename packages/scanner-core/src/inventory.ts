import fs from "node:fs/promises";
import path from "node:path";
import { listScannableFiles } from "./fileWalker.js";

export interface PackageScript {
  name: string;
  command: string;
  filePath: string;
}

export interface ProjectInventory {
  files: string[];
  packageScripts: PackageScript[];
  dependencySources: string[];
  environmentVariables: string[];
  networkEndpoints: string[];
  commandExecutions: Array<{ filePath: string; line: number; snippet: string }>;
  filesystemReads: Array<{ filePath: string; line: number; snippet: string }>;
  githubWorkflowFiles: string[];
  electronIpcFiles: string[];
  persistenceIndicators: Array<{ filePath: string; line: number; snippet: string }>;
}

export async function buildInventory(rootDir: string): Promise<ProjectInventory> {
  const files = await listScannableFiles(rootDir);
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
    collectRegex(content, /https?:\/\/[^\s"'`)]+/g, (match) => inventory.networkEndpoints.push(match[0]));
    collectLineMatches(content, filePath, /(child_process|exec\(|spawn\(|execFile\(|curl\s+.*\|\s*bash)/, inventory.commandExecutions);
    collectLineMatches(content, filePath, /(readFileSync|readFile\(|createReadStream)/, inventory.filesystemReads);
    collectLineMatches(content, filePath, /(LaunchAgent|systemd|crontab|Startup|RunOnce|pm2|daemon)/i, inventory.persistenceIndicators);

    if (/ipcMain\.(handle|on)|contextBridge|nodeIntegration|contextIsolation/.test(content)) {
      inventory.electronIpcFiles.push(filePath);
    }
  }

  inventory.environmentVariables = unique(inventory.environmentVariables);
  inventory.networkEndpoints = unique(inventory.networkEndpoints);
  inventory.dependencySources = unique(inventory.dependencySources);

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

  for (const deps of [parsed.dependencies, parsed.devDependencies]) {
    if (!isRecord(deps)) {
      continue;
    }

    for (const source of Object.values(deps)) {
      if (typeof source !== "string") {
        continue;
      }

      if (source.startsWith("github:") || source.startsWith("git+") || source.startsWith("http") || source.startsWith("file:")) {
        inventory.dependencySources.push(source);
      }
    }
  }
}

function collectRegex(content: string, regex: RegExp, onMatch: (match: RegExpExecArray) => void): void {
  for (let match = regex.exec(content); match; match = regex.exec(content)) {
    onMatch(match);
  }
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
