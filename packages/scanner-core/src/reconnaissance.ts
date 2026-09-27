import fs from "node:fs/promises";
import path from "node:path";
import { listScannableFiles } from "./fileWalker.js";
import type { ProjectInventory } from "./inventory.js";
import type { LanguageId } from "./types.js";

export interface ArchitectureSummary {
  applicationType: string;
  techStack: {
    languages: LanguageId[];
    frameworks: string[];
    databases: string[];
    runtime: string;
    deploymentModel: string;
  };
  trustModel: {
    actors: string[];
    trustBoundaries: TrustBoundary[];
    authentication: string[];
    authorization: string[];
    privilegeSeparation: string[];
    bypassMechanisms: string[];
  };
  inputSurfaces: InputSurface[];
  keyEntryPoints: string[];
  comparableBaseline: string;
  coverageLedger: CoverageLedger;
}

export interface TrustBoundary {
  name: string;
  description: string;
  entryPoints: string[];
  enforcementCode: string[];
}

export interface InputSurface {
  type: "network" | "file" | "ipc" | "user-content" | "external-integration" | "cli" | "env";
  description: string;
  locations: string[];
  dangerousSinks: string[];
}

export interface CoverageLedger {
  version: number;
  units: CoverageUnit[];
  lastUpdated: string;
}

export interface CoverageUnit {
  id: string;
  type: "attack-class" | "subsystem" | "entry-point";
  name: string;
  description: string;
  status: "unexplored" | "in-progress" | "covered" | "gap-detected";
  findings: string[];
  assignedHunter?: string;
  startedAt?: string;
  completedAt?: string;
}

export async function runReconnaissance(targetPath: string, inventory: ProjectInventory): Promise<ArchitectureSummary> {
  const files = await listScannableFiles(targetPath);
  const fileContents = new Map<string, string>();

  for (const file of files) {
    const fullPath = path.join(targetPath, file);
    const content = await fs.readFile(fullPath, "utf8").catch(() => "");
    if (content) fileContents.set(file, content);
  }

  const applicationType = detectApplicationType(fileContents);
  const techStack = detectTechStack(fileContents, files);
  const trustModel = analyzeTrustBoundaries(fileContents, files);
  const inputSurfaces = analyzeInputSurfaces(fileContents, files, inventory);
  const keyEntryPoints = findKeyEntryPoints(fileContents, files);
  const comparableBaseline = determineComparableBaseline(applicationType, techStack);
  const coverageLedger = initializeCoverageLedger(applicationType, inputSurfaces, trustModel);

  return {
    applicationType,
    techStack,
    trustModel,
    inputSurfaces,
    keyEntryPoints,
    comparableBaseline,
    coverageLedger
  };
}

function detectApplicationType(fileContents: Map<string, string>): string {
  const hasPackageJson = fileContents.has("package.json");
  const hasDockerfile = Array.from(fileContents.keys()).some(f => f.toLowerCase().includes("dockerfile"));
  const hasPythonFiles = Array.from(fileContents.keys()).some(f => f.endsWith(".py"));
  const hasGoFiles = Array.from(fileContents.keys()).some(f => f.endsWith(".go"));
  const hasJavaFiles = Array.from(fileContents.keys()).some(f => f.endsWith(".java"));
  const hasElectron = Array.from(fileContents.values()).some(c => c.includes("electron") || c.includes("BrowserWindow"));
  const hasExpress = Array.from(fileContents.values()).some(c => c.includes("express"));
  const hasFastify = Array.from(fileContents.values()).some(c => c.includes("fastify"));
  const hasNextjs = Array.from(fileContents.values()).some(c => c.includes("next/") || c.includes("nextjs"));
  const hasCli = Array.from(fileContents.values()).some(c => c.includes("commander") || c.includes("yargs") || c.includes("cli"));

  if (hasElectron) return "desktop-app (Electron)";
  if (hasNextjs) return "web-app (Next.js)";
  if (hasExpress || hasFastify) return "web-api (Node.js)";
  if (hasCli) return "cli-tool";
  if (hasPythonFiles) return "python-application";
  if (hasGoFiles) return "go-service";
  if (hasJavaFiles) return "java-application";
  if (hasDockerfile) return "containerized-service";
  if (hasPackageJson) return "node-library";
  return "unknown";
}

function detectTechStack(fileContents: Map<string, string>, files: string[]): ArchitectureSummary["techStack"] {
  const languages: LanguageId[] = [];
  const frameworks: string[] = [];
  const databases: string[] = [];

  for (const [file, content] of fileContents) {
    if (file.endsWith(".py")) languages.push("python");
    if (file.match(/\.(js|jsx|ts|tsx|mjs|cjs)$/)) languages.push("javascript");
    if (file.endsWith(".go")) languages.push("go");
    if (file.endsWith(".java")) languages.push("java");
    if (file.match(/\.(sh|bash|zsh)$/)) languages.push("shell");
    if (file.toLowerCase().includes("dockerfile")) languages.push("dockerfile");
    if (file.match(/\.(ya?ml)$/)) languages.push("yaml");

    if (content.includes("express")) frameworks.push("express");
    if (content.includes("fastify")) frameworks.push("fastify");
    if (content.includes("next/")) frameworks.push("nextjs");
    if (content.includes("react")) frameworks.push("react");
    if (content.includes("vue")) frameworks.push("vue");
    if (content.includes("electron")) frameworks.push("electron");
    if (content.includes("django")) frameworks.push("django");
    if (content.includes("flask")) frameworks.push("flask");
    if (content.includes("spring")) frameworks.push("spring");
    if (content.includes("gin")) frameworks.push("gin");
    if (content.includes("echo")) frameworks.push("echo");

    if (content.includes("postgres") || content.includes("postgresql")) databases.push("postgresql");
    if (content.includes("mysql")) databases.push("mysql");
    if (content.includes("mongodb") || content.includes("mongoose")) databases.push("mongodb");
    if (content.includes("redis")) databases.push("redis");
    if (content.includes("sqlite")) databases.push("sqlite");
  }

  return {
    languages: [...new Set(languages)],
    frameworks: [...new Set(frameworks)],
    databases: [...new Set(databases)],
    runtime: languages.includes("javascript") ? "Node.js" : languages.includes("python") ? "Python" : languages.includes("go") ? "Go" : "unknown",
    deploymentModel: "unknown"
  };
}

function analyzeTrustBoundaries(fileContents: Map<string, string>, files: string[]): ArchitectureSummary["trustModel"] {
  const actors: string[] = ["external-user", "authenticated-user", "admin", "service-account"];
  const trustBoundaries: TrustBoundary[] = [];
  const authentication: string[] = [];
  const authorization: string[] = [];
  const privilegeSeparation: string[] = [];
  const bypassMechanisms: string[] = [];

  for (const [file, content] of fileContents) {
    if (content.includes("passport") || content.includes("jwt") || content.includes("session") || content.includes("auth")) {
      authentication.push(`${file}: authentication middleware detected`);
    }
    if (content.includes("rbac") || content.includes("permission") || content.includes("authorize") || content.includes("can(")) {
      authorization.push(`${file}: authorization logic detected`);
    }
    if (content.includes("sudo") || content.includes("setuid") || content.includes("drop privileges") || content.includes("worker_threads")) {
      privilegeSeparation.push(`${file}: privilege separation detected`);
    }
    if (content.includes("dev") || content.includes("debug") || content.includes("test") || content.includes("bypass")) {
      bypassMechanisms.push(`${file}: potential bypass mechanism`);
    }
  }

  trustBoundaries.push({
    name: "network-boundary",
    description: "External network requests enter the system",
    entryPoints: files.filter(f => f.includes("route") || f.includes("handler") || f.includes("controller") || f.includes("api")),
    enforcementCode: authentication
  });

  trustBoundaries.push({
    name: "file-system-boundary",
    description: "File reads/writes from untrusted sources",
    entryPoints: files.filter(f => f.includes("upload") || f.includes("import") || f.includes("readFile")),
    enforcementCode: []
  });

  return {
    actors,
    trustBoundaries,
    authentication,
    authorization,
    privilegeSeparation,
    bypassMechanisms
  };
}

function analyzeInputSurfaces(fileContents: Map<string, string>, files: string[], inventory: ProjectInventory): InputSurface[] {
  const surfaces: InputSurface[] = [];

  if (inventory.networkEndpoints.length > 0) {
    surfaces.push({
      type: "network",
      description: "HTTP/HTTPS endpoints accepting external requests",
      locations: [...new Set(inventory.networkEndpoints.map(e => e.filePath))],
      dangerousSinks: ["sql-query", "html-output", "shell-command", "file-path", "deserialization"]
    });
  }

  if (inventory.filesystemReads.length > 0) {
    surfaces.push({
      type: "file",
      description: "File system reads from potentially untrusted paths",
      locations: [...new Set(inventory.filesystemReads.map(r => r.filePath))],
      dangerousSinks: ["path-traversal", "deserialization", "code-execution"]
    });
  }

  if (inventory.electronIpcFiles.length > 0) {
    surfaces.push({
      type: "ipc",
      description: "Electron IPC channels between renderer and main process",
      locations: inventory.electronIpcFiles,
      dangerousSinks: ["node-integration", "context-bridge", "ipc-main-handle"]
    });
  }

  if (inventory.environmentVariables.length > 0) {
    surfaces.push({
      type: "env",
      description: "Environment variable access",
      locations: [...new Set(files)],
      dangerousSinks: ["command-injection", "config-manipulation"]
    });
  }

  if (inventory.packageScripts.length > 0) {
    surfaces.push({
      type: "cli",
      description: "npm lifecycle scripts and CLI commands",
      locations: ["package.json"],
      dangerousSinks: ["shell-execution", "supply-chain"]
    });
  }

  return surfaces;
}

function findKeyEntryPoints(fileContents: Map<string, string>, files: string[]): string[] {
  const entryPoints: string[] = [];

  for (const file of files) {
    const content = fileContents.get(file);
    if (!content) continue;

    if (file.includes("main") || file.includes("index") || file.includes("app.") || file.includes("server.")) {
      entryPoints.push(file);
    }
    if (content.includes("export default") || content.includes("module.exports")) {
      entryPoints.push(file);
    }
  }

  return [...new Set(entryPoints)];
}

function determineComparableBaseline(applicationType: string, techStack: ArchitectureSummary["techStack"]): string {
  const baselines: Record<string, string> = {
    "desktop-app (Electron)": "VS Code, Discord, Slack - Electron apps with context isolation, no nodeIntegration, strict CSP",
    "web-app (Next.js)": "Vercel, Netlify apps - SSR with strict output encoding, CSP, secure headers",
    "web-api (Node.js)": "Express/Fastify APIs - input validation, rate limiting, auth middleware, helmet.js",
    "cli-tool": "npm, yarn, pnpm - argument validation, no shell injection, signed releases",
    "python-application": "Django, FastAPI - ORM prevents SQLi, template auto-escaping, CSRF protection",
    "go-service": "Standard library net/http - explicit error handling, no reflection on untrusted input",
    "java-application": "Spring Boot - Spring Security, parameterized queries, deserialization guards",
    "containerized-service": "Distroless, gVisor - minimal attack surface, no shell, read-only rootfs",
    "node-library": "lodash, axios - no runtime code execution, pure functions, semantic versioning"
  };

  return baselines[applicationType] || "No direct comparable; apply general secure coding practices";
}

function initializeCoverageLedger(applicationType: string, inputSurfaces: InputSurface[], trustModel: ArchitectureSummary["trustModel"]): CoverageLedger {
  const units: CoverageUnit[] = [];
  let unitId = 0;

  const attackClasses = selectAttackClasses(applicationType, inputSurfaces);

  for (const attackClass of attackClasses) {
    units.push({
      id: `unit-${++unitId}`,
      type: "attack-class",
      name: attackClass,
      description: `Coverage for ${attackClass} vulnerabilities`,
      status: "unexplored",
      findings: []
    });
  }

  for (const surface of inputSurfaces) {
    units.push({
      id: `unit-${++unitId}`,
      type: "entry-point",
      name: surface.type,
      description: `Coverage for ${surface.type} input surface`,
      status: "unexplored",
      findings: []
    });
  }

  for (const boundary of trustModel.trustBoundaries) {
    units.push({
      id: `unit-${++unitId}`,
      type: "subsystem",
      name: boundary.name,
      description: `Coverage for ${boundary.name} trust boundary`,
      status: "unexplored",
      findings: []
    });
  }

  return {
    version: 1,
    units,
    lastUpdated: new Date().toISOString()
  };
}

function selectAttackClasses(applicationType: string, inputSurfaces: InputSurface[]): string[] {
  const baseClasses = ["injection", "access-control", "resource-file-handling", "cryptography-secrets"];
  const typeSpecific: Record<string, string[]> = {
    "desktop-app (Electron)": ["electron-ipc", "prototype-pollution", "context-isolation-bypass"],
    "web-app (Next.js)": ["xss", "csrf", "ssrf", "open-redirect"],
    "web-api (Node.js)": ["sql-injection", "nosql-injection", "ssrf", "rate-limit-bypass"],
    "cli-tool": ["command-injection", "path-traversal", "supply-chain"],
    "python-application": ["pickle-deserialization", "template-injection", "sql-injection"],
    "go-service": ["template-injection", "yaml-deserialization", "path-traversal"],
    "java-application": ["deserialization", "jndi-injection", "xpath-injection", "spel-injection"],
    "containerized-service": ["container-escape", "supply-chain", "secrets-in-image"],
    "node-library": ["prototype-pollution", "re-dos", "supply-chain"]
  };

  const specific = typeSpecific[applicationType] || [];
  const surfaceSpecific = inputSurfaces.flatMap(s => {
    switch (s.type) {
      case "network": return ["ssrf", "open-redirect", "http-smuggling"];
      case "file": return ["path-traversal", "zip-slip", "unsafe-deserialization"];
      case "ipc": return ["ipc-abuse", "context-bridge-bypass"];
      case "user-content": return ["xss", "template-injection", "stored-xss"];
      case "external-integration": return ["webhook-abuse", "oauth-bypass", "supply-chain"];
      case "cli": return ["command-injection", "arg-injection"];
      case "env": return ["env-injection", "config-manipulation"];
      default: return [];
    }
  });

  return [...new Set([...baseClasses, ...specific, ...surfaceSpecific])];
}

export function updateCoverageLedger(ledger: CoverageLedger, unitId: string, status: CoverageUnit["status"], findings: string[] = [], hunter?: string): CoverageLedger {
  const updated = { ...ledger, units: ledger.units.map(u => {
    if (u.id === unitId) {
      return { ...u, status, findings: [...new Set([...u.findings, ...findings])], assignedHunter: hunter ?? u.assignedHunter, completedAt: status === "covered" || status === "gap-detected" ? new Date().toISOString() : u.completedAt };
    }
    return u;
  }), lastUpdated: new Date().toISOString() };
  return updated;
}

export function findCoverageGaps(ledger: CoverageLedger): CoverageUnit[] {
  return ledger.units.filter(u => u.status === "unexplored" || u.status === "gap-detected");
}

export function serializeCoverageLedger(ledger: CoverageLedger): string {
  return JSON.stringify(ledger, null, 2);
}

export function deserializeCoverageLedger(json: string): CoverageLedger {
  return JSON.parse(json);
}