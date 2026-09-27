import type { FindingCategory, RiskLevel } from "./types.js";
import type { ArchitectureSummary, CoverageLedger, CoverageUnit } from "./reconnaissance.js";
import type { ProjectInventory } from "./inventory.js";

import fs from "node:fs/promises";
import path from "node:path";

export interface HunterResult {
  unitId: string;
  hunterName: string;
  candidates: CandidateFinding[];
  coverageNotes: string[];
  gapsFound: string[];
}

export interface CandidateFinding {
  id: string;
  category: FindingCategory;
  riskLevel: RiskLevel;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  codeSnippet: string;
  explanation: string;
  recommendedFix: string;
  evidenceTags: string[];
  confidence: "High" | "Medium" | "Low";
  source?: string;
  sink?: string;
  dataFlowId?: string;
  attackVector: string;
  reproductionSteps: string[];
  disproofAttempts: string[];
}

export interface AttackClassPrompt {
  name: string;
  description: string;
  methodology: string;
  validationRules: string;
  relevantSurfaces: string[];
  relevantBoundaries: string[];
}

export const ATTACK_CLASS_PROMPTS: Record<string, AttackClassPrompt> = {
  injection: {
    name: "Injection",
    description: "Trace untrusted input from entry point to dangerous sink",
    methodology: `
## How to hunt for injection

Don't just check if defenses exist. Try to break them.

READ THE CODE AT DEPTH. Don't stop at the first function. Follow the data through
every layer — from the entry point through validation, transformation, storage, retrieval,
and output. Bugs live in the gaps between layers.

Think about these angles:

1. THE HAPPY PATH IS DEFENDED. ATTACK THE SAD PATH.
   Error handlers, fallback branches, catch blocks, default cases, timeout paths,
   retry logic, cleanup routines. What happens when things fail? Are errors handled
   with the same rigor as success? Does a failed validation leave state half-modified?

2. WHAT HAPPENS AT BOUNDARIES?
   Empty input. Maximum-length input. Null vs undefined vs missing. Zero. Negative numbers.
   Unicode edge cases. The first item and the last item. One more than the maximum. Exactly
   at the rate limit. The moment a token expires.

3. WHAT DO COMPONENTS ASSUME ABOUT EACH OTHER?
   Does the database layer assume the API layer validated input? Does the renderer assume
   content was sanitized on write? Does the auth middleware assume routes register themselves
   correctly? Find where trust is implicit and test whether it's justified.

4. WHAT IF OPERATIONS HAPPEN IN THE WRONG ORDER?
   Call step 3 before step 1. Call delete during create. Send the callback before the request.
   Hit the confirmation endpoint without starting the flow. Replay a completed flow.

5. WHAT IF TWO THINGS HAPPEN AT ONCE?
   Race conditions between check and use. Two requests modifying the same resource.
   Concurrent sessions for the same user.`,
    validationRules: `
## Validation rules for injection candidates

A candidate is CONFIRMED only if:
- You can trace a complete path from untrusted input to dangerous sink
- The path has NO validation, OR validation that can be bypassed
- You can describe a concrete exploit payload

A candidate NEEDS_VALIDATION if:
- There's a path but you're unsure if validation is sufficient
- The sink is dangerous but input source is unclear
- You need deeper code review to confirm

A candidate is REJECTED if:
- Input is validated/sanitized before the sink with no bypass
- The sink is not actually dangerous in this context
- The code path is unreachable from untrusted input`,
    relevantSurfaces: ["network", "file", "user-content", "external-integration", "cli", "ipc"],
    relevantBoundaries: ["network-boundary", "file-system-boundary"]
  },
  "access-control": {
    name: "Access Control",
    description: "Can a caller do something they shouldn't? Verify permission checks are correct",
    methodology: `
## How to hunt for access control issues

Go beyond checking whether permission checks exist — verify they check the *right*
permission for the *right* resource via the *right* mechanism:

- Is there a path to the same state change that checks a different (weaker) permission?
- Can a field in the request body override what the permission system intended to restrict?
- Are there endpoints that gate on authentication but forget authorization?
- Does the same resource have multiple access paths with inconsistent checks?
- What about bulk/batch/export/import operations — do they enforce per-item permissions?
- Can you escalate by manipulating IDs, roles, or scopes in the request?
- Are there horizontal privilege escalation paths (accessing other users' data)?
- Vertical escalation: can a low-privilege user reach admin functionality?`,
    validationRules: `
## Validation rules for access control candidates

A candidate is CONFIRMED only if:
- You can demonstrate a concrete bypass or escalation path
- The permission check is missing, wrong, or inconsistent
- You can describe exact request/steps to reproduce

A candidate NEEDS_VALIDATION if:
- Permission logic is complex and you can't fully trace it
- There's a potential bypass but you can't construct a working exploit
- You need to understand the authorization model better

A candidate is REJECTED if:
- Permission checks are correct and consistent across all paths
- The alleged bypass is blocked by another layer
- The operation is correctly scoped to the caller's permissions`,
    relevantSurfaces: ["network", "ipc", "user-content"],
    relevantBoundaries: ["network-boundary"]
  },
  "resource-file-handling": {
    name: "Resource and File Handling",
    description: "Path traversal, SSRF, unsafe deserialization, archive extraction, race conditions",
    methodology: `
## How to hunt for resource/file handling issues

- Path traversal (reading/writing outside intended directories) — including through symlinks, encoded sequences, and null bytes
- SSRF (making the application fetch attacker-controlled URLs) — including through redirects, DNS rebinding, and URL parser differentials
- Unsafe deserialization, archive extraction (zip slip), temp file handling
- Memory safety (if applicable): buffer overflows, use-after-free, integer overflow
- Race conditions on file operations (TOCTOU between check and use)
- Insecure temporary file creation
- Symlink following without validation
- Archive extraction without path validation (zip slip)
- XML external entity (XXE) processing
- Unsafe YAML/JSON deserialization with type confusion`,
    validationRules: `
## Validation rules for resource/file handling candidates

A candidate is CONFIRMED only if:
- You can trace untrusted input to a file/URL operation without proper validation
- Path canonicalization is missing or bypassable
- SSRF: internal network access is possible via the fetch
- Deserialization: attacker controls type/class being instantiated

A candidate NEEDS_VALIDATION if:
- Validation exists but you're unsure if it's sufficient
- The sink is dangerous but exploitability depends on environment
- Race condition window is theoretical

A candidate is REJECTED if:
- Paths are properly canonicalized and validated against allowlist
- SSRF: fetch targets are restricted to allowlist
- Deserialization: safe library with type allowlist used
- Race: atomic operations or proper locking used`,
    relevantSurfaces: ["network", "file", "external-integration"],
    relevantBoundaries: ["network-boundary", "file-system-boundary"]
  },
  "cryptography-secrets": {
    name: "Cryptography and Secrets",
    description: "Weak randomness, hardcoded secrets, broken key derivation, timing side-channels",
    methodology: `
## How to hunt for cryptography and secrets issues

- Weak randomness for security-critical values (tokens, keys, nonces) — Math.random(), non-CSPRNG
- Hardcoded secrets, secrets in logs, error messages, URLs, or client-visible responses
- Broken key derivation, missing HMAC verification, nonce reuse
- Timing side-channels on secret comparison (== vs constant-time compare)
- Misuse of crypto primitives (ECB mode, unauthenticated encryption, static IVs, etc.)
- What happens when crypto operations fail? Does the error leak information?
- Certificate validation bypasses (pinning, hostname verification)
- Weak password hashing (MD5, SHA1, unsalted, low iterations)
- Insecure key storage (plaintext, world-readable files, repo commits)
- JWT: none algorithm, weak secrets, missing expiration, algorithm confusion`,
    validationRules: `
## Validation rules for cryptography/secrets candidates

A candidate is CONFIRMED only if:
- You found actual weak crypto usage (not theoretical)
- Secrets are actually exposed (not just "could be")
- Timing attack is feasible (remote, measurable difference)
- Key derivation is demonstrably weak

A candidate NEEDS_VALIDATION if:
- Crypto usage looks suspicious but you can't confirm exploitability
- Secret might be in a test/fixture file
- Algorithm choice is unusual but not obviously broken

A candidate is REJECTED if:
- CSPRNG used for security-critical values
- Secrets are properly managed (env, vault, keyring)
- Constant-time comparison used for secrets
- Authenticated encryption with proper IV/nonce management`,
    relevantSurfaces: ["network", "file", "env", "external-integration"],
    relevantBoundaries: ["network-boundary", "file-system-boundary"]
  },
  "electron-ipc": {
    name: "Electron IPC Security",
    description: "Context isolation bypass, nodeIntegration abuse, preload script issues, contextBridge exposure",
    methodology: `
## How to hunt for Electron IPC issues

- contextIsolation: false or not set — renderer has direct Node.js access
- nodeIntegration: true — renderer can require() Node modules
- preload scripts exposing dangerous APIs via contextBridge
- ipcMain.handle/on handlers without sender validation
- contextBridge exposing electron, node, or fs modules directly
- webPreferences: sandbox: false, allowRunningInsecureContent: true
- Remote module enabled (deprecated but still in old code)
- child_process, fs, os exposed to renderer
- eval/Function in preload or renderer
- Untrusted content loaded in webview without partition
- devTools enabled in production
- CSP missing or weak (no script-src, allows unsafe-inline/eval)`,
    validationRules: `
## Validation rules for Electron IPC candidates

A candidate is CONFIRMED only if:
- contextIsolation is disabled or bypassable
- Dangerous APIs (fs, child_process, electron) exposed to renderer
- IPC handlers accept unvalidated input from renderer
- CSP allows unsafe-inline/eval in production

A candidate NEEDS_VALIDATION if:
- Configuration is complex and you can't confirm runtime state
- Preload exposes limited API but you're unsure if it's safe
- webview partition isolation needs verification

A candidate is REJECTED if:
- contextIsolation: true, nodeIntegration: false, sandbox: true
- contextBridge exposes only safe, validated functions
- IPC handlers validate sender and all input
- Strong CSP with nonce/hashes, no unsafe-inline/eval`,
    relevantSurfaces: ["ipc", "network", "file"],
    relevantBoundaries: ["network-boundary", "file-system-boundary"]
  },
  "supply-chain": {
    name: "Supply Chain",
    description: "Unpinned dependencies, malicious packages, build integrity, CI/CD compromise",
    methodology: `
## How to hunt for supply chain issues

- Unpinned dependencies (git, HTTP, tarball, local file, version ranges)
- Dependencies from untrusted registries or scopes
- Install-time scripts (postinstall, prepare) that execute code
- Dockerfile ADD/COPY from remote without checksums
- Dockerfile RUN curl|sh or wget|sh during build
- GitHub Actions: pull_request_target with fork code checkout
- GitHub Actions: unpinned third-party actions (not full SHA)
- GitHub Actions: self-hosted runners without isolation
- CI secrets exposed in logs or to fork PRs
- Dependency confusion (internal package names on public registry)
- Typosquatting (similar package names)
- Compromised maintainer accounts / malicious publishes
- Lockfile integrity not verified
- SBOM missing or incomplete`,
    validationRules: `
## Validation rules for supply chain candidates

A candidate is CONFIRMED only if:
- Unpinned/remote dependency actually used in production build
- Install script executes with network access
- CI/CD has demonstrable secret exposure or fork code execution
- Action pinned to mutable tag (not SHA)

A candidate NEEDS_VALIDATION if:
- Dependency looks suspicious but not confirmed malicious
- CI config has risky pattern but runtime behavior unclear
- Internal package name exists on public registry

A candidate is REJECTED if:
- All deps pinned to registry versions with lockfile
- No install-time scripts or they're safe
- Actions pinned to full commit SHAs
- CI secrets properly scoped, no fork exposure`,
    relevantSurfaces: ["cli", "external-integration", "file"],
    relevantBoundaries: ["file-system-boundary"]
  }
};

export async function runHuntingPhase(
  architecture: ArchitectureSummary,
  inventory: ProjectInventory,
  ledger: CoverageLedger,
  options: { maxHunters?: number; targetDir?: string } = {}
): Promise<{ results: HunterResult[]; updatedLedger: CoverageLedger }> {
  const unexploredUnits = ledger.units.filter(u => u.status === "unexplored" || u.status === "gap-detected");
  const huntersToLaunch = unexploredUnits.slice(0, options.maxHunters ?? 8);
  const targetDir = options.targetDir ?? "";

  const results: HunterResult[] = [];
  let updatedLedger = ledger;

  for (const unit of huntersToLaunch) {
    const prompt = ATTACK_CLASS_PROMPTS[unit.name] || ATTACK_CLASS_PROMPTS.injection;
    const hunterResult = await simulateHunter(unit, prompt, architecture, inventory, targetDir);
    results.push(hunterResult);

    updatedLedger = updateCoverageLedgerFromHunter(updatedLedger, hunterResult);
  }

  return { results, updatedLedger };
}

async function simulateHunter(
  unit: CoverageUnit,
  prompt: AttackClassPrompt,
  architecture: ArchitectureSummary,
  inventory: ProjectInventory,
  targetDir: string
): Promise<HunterResult> {
  const candidates: CandidateFinding[] = [];
  const coverageNotes: string[] = [];
  const gapsFound: string[] = [];

  const relevantFiles = findRelevantFiles(unit, architecture, inventory);

  for (const file of relevantFiles) {
    const fileCandidates = await huntInFile(unit.name, file, inventory, prompt, targetDir);
    candidates.push(...fileCandidates);
  }

  if (candidates.length === 0) {
    gapsFound.push(`No ${unit.name} vulnerabilities found in ${relevantFiles.length} relevant files`);
  } else {
    coverageNotes.push(`Found ${candidates.length} candidate(s) in ${unit.name}`);
  }

  const status = candidates.length > 0 ? "covered" : "gap-detected";

  return {
    unitId: unit.id,
    hunterName: `hunter-${unit.name}`,
    candidates,
    coverageNotes,
    gapsFound
  };
}

function findRelevantFiles(unit: CoverageUnit, architecture: ArchitectureSummary, inventory: ProjectInventory): string[] {
  const files = new Set<string>();

  if (unit.type === "attack-class") {
    const prompt = ATTACK_CLASS_PROMPTS[unit.name];
    if (prompt) {
      for (const surfaceType of prompt.relevantSurfaces) {
        const surface = architecture.inputSurfaces.find(s => s.type === surfaceType);
        if (surface) surface.locations.forEach(f => files.add(f));
      }
      for (const boundaryName of prompt.relevantBoundaries) {
        const boundary = architecture.trustModel.trustBoundaries.find(b => b.name === boundaryName);
        if (boundary) boundary.entryPoints.forEach(f => files.add(f));
      }
    }
  } else if (unit.type === "entry-point") {
    const surface = architecture.inputSurfaces.find(s => s.type === unit.name);
    if (surface) surface.locations.forEach(f => files.add(f));
  } else if (unit.type === "subsystem") {
    const boundary = architecture.trustModel.trustBoundaries.find(b => b.name === unit.name);
    if (boundary) boundary.entryPoints.forEach(f => files.add(f));
  }

  return Array.from(files);
}

async function huntInFile(
  attackClass: string,
  filePath: string,
  inventory: ProjectInventory,
  prompt: AttackClassPrompt,
  targetDir: string
): Promise<CandidateFinding[]> {
  const findings: CandidateFinding[] = [];

  const dangerousCalls = inventory.dangerousCalls.filter(d => d.filePath === filePath);
  const threatSignals = inventory.threatSignals.filter(t => t.filePath === filePath);
  const networkEndpoints = inventory.networkEndpoints.filter(n => n.filePath === filePath);
  const commandExecutions = inventory.commandExecutions.filter(c => c.filePath === filePath);
  const filesystemReads = inventory.filesystemReads.filter(f => f.filePath === filePath);

  switch (attackClass) {
    case "injection":
      findings.push(...huntInjection(filePath, dangerousCalls, threatSignals, networkEndpoints, commandExecutions));
      break;
    case "access-control":
      findings.push(...huntAccessControl(filePath, networkEndpoints, inventory));
      break;
    case "resource-file-handling":
      findings.push(...huntResourceFile(filePath, filesystemReads, networkEndpoints, inventory));
      break;
    case "cryptography-secrets":
      findings.push(...await huntCryptoSecrets(filePath, targetDir));
      break;
    case "electron-ipc":
      findings.push(...huntElectronIpc(filePath, inventory));
      break;
    case "supply-chain":
      findings.push(...huntSupplyChain(filePath, inventory));
      break;
  }

  return findings;
}

function huntInjection(
  filePath: string,
  dangerousCalls: any[],
  threatSignals: any[],
  networkEndpoints: any[],
  commandExecutions: any[]
): CandidateFinding[] {
  const findings: CandidateFinding[] = [];
  const directSinkPatterns = [
    "javascript.eval",
    "python.eval",
    "javascript.child_process",
    "python.subprocess",
    "go.exec",
    "java.runtime_exec",
    "java.process_builder",
    "shell.curl_sh",
    "shell.eval",
    "shell.base64_sh",
    "dockerfile.curl_sh"
  ];

  const makeCandidate = (
    opts: {
      category: CandidateFinding["category"];
      riskLevel: CandidateFinding["riskLevel"];
      line: number;
      snippet: string;
      explanation: string;
      recommendedFix: string;
      tags: string[];
      sink: string;
      attackVector: string;
    }
  ): CandidateFinding => ({
    id: `candidate-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
    category: opts.category,
    riskLevel: opts.riskLevel,
    filePath,
    lineStart: opts.line,
    lineEnd: opts.line,
    codeSnippet: opts.snippet,
    explanation: opts.explanation,
    recommendedFix: opts.recommendedFix,
    evidenceTags: [...opts.tags, "injection-candidate"],
    confidence: "High",
    source: "untrusted input (CLI arg, request param, env var, or user-controlled file)",
    sink: opts.sink,
    attackVector: opts.attackVector,
    reproductionSteps: ["Identify input source", "Trace data flow to sink", "Craft bypass payload"],
    disproofAttempts: ["Check for input validation", "Verify sanitization", "Confirm sink safety"]
  });

  for (const call of dangerousCalls) {
    const isDirectSink = directSinkPatterns.includes(call.pattern);
    findings.push(
      makeCandidate({
        category: call.pattern.includes("eval") ? "remote-code-execution" : "command-injection",
        riskLevel: isDirectSink ? "Critical" : "High",
        line: call.line,
        snippet: call.snippet,
        explanation: `Dangerous call ${call.pattern} found. Trace whether untrusted input reaches this sink.`,
        recommendedFix: "Validate and sanitize all input before passing to dangerous sinks. Use parameterized APIs.",
        tags: [...call.evidenceTags],
        sink: call.pattern,
        attackVector: "Untrusted input → validation gap → dangerous sink"
      })
    );
  }

  for (const exec of commandExecutions) {
    findings.push(
      makeCandidate({
        category: "command-injection",
        riskLevel: exec.snippet.includes("| bash") || exec.snippet.includes("| sh") ? "Critical" : "High",
        line: exec.line,
        snippet: exec.snippet,
        explanation:
          "Shell/process execution site found. If user-controlled data reaches this call it becomes command injection or RCE.",
        recommendedFix:
          "Use explicit argument arrays (execFile/spawn) without shell interpretation and validate all input.",
        tags: ["command-execution"],
        sink: "child-process-exec",
        attackVector: "Untrusted input → exec()/spawn() with shell → command injection"
      })
    );
  }

  for (const signal of threatSignals) {
    if (!["ssrf-sink", "webhook-sink", "encoded-sink", "non-http-sink", "file-upload-sink"].includes(signal.pattern)) {
      continue;
    }
    findings.push(
      makeCandidate({
        category: "data-exfiltration",
        riskLevel: "High",
        line: signal.line,
        snippet: signal.snippet,
        explanation: `Outbound exfiltration sink (${signal.pattern}) found. Verify whether sensitive data can flow to this destination.`,
        recommendedFix: "Remove unauthorized outbound channels; route data only through approved, audited endpoints.",
        tags: [...signal.evidenceTags],
        sink: signal.pattern,
        attackVector: "Sensitive source (env var, fs read) → outbound sink → data exfiltration"
      })
    );
  }

  return findings;
}

function huntAccessControl(filePath: string, networkEndpoints: any[], inventory: ProjectInventory): CandidateFinding[] {
  const findings: CandidateFinding[] = [];

  for (const endpoint of networkEndpoints) {
    findings.push({
      id: `candidate-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
      category: "network",
      riskLevel: "Medium",
      filePath,
      lineStart: endpoint.line,
      lineEnd: endpoint.line,
      codeSnippet: endpoint.snippet,
      explanation: `Network endpoint detected. Verify authorization checks are present and correct for this route.`,
      recommendedFix: "Add authorization middleware; verify permissions per resource; test horizontal/vertical escalation.",
      evidenceTags: ["access-control-candidate", "endpoint"],
      confidence: "Low",
      attackVector: "Unauthenticated/unauthorized request → missing auth check → privileged operation",
      reproductionSteps: ["Identify endpoint", "Check auth middleware", "Test without auth", "Test with low-privilege auth"],
      disproofAttempts: ["Find auth middleware", "Verify permission checks", "Test escalation paths"]
    });
  }

  return findings;
}

function huntResourceFile(
  filePath: string,
  filesystemReads: any[],
  networkEndpoints: any[],
  inventory: ProjectInventory
): CandidateFinding[] {
  const findings: CandidateFinding[] = [];

  for (const read of filesystemReads) {
    findings.push({
      id: `candidate-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
      category: "filesystem",
      riskLevel: "High",
      filePath,
      lineStart: read.line,
      lineEnd: read.line,
      codeSnippet: read.snippet,
      explanation: `File system read detected. Verify path validation prevents traversal and SSRF.`,
      recommendedFix: "Canonicalize paths; validate against allowlist; use safe path resolution APIs.",
      evidenceTags: ["path-traversal-candidate", "file-read"],
      confidence: "Medium",
      attackVector: "User-controlled path → insufficient validation → arbitrary file read",
      reproductionSteps: ["Identify path input", "Test traversal payloads", "Verify canonicalization"],
      disproofAttempts: ["Check path validation", "Test symlink handling", "Verify allowlist"]
    });
  }

  for (const endpoint of networkEndpoints) {
    if (endpoint.endpoint.includes("localhost") || endpoint.endpoint.includes("127.0.0.1") || endpoint.endpoint.includes("internal")) {
      findings.push({
        id: `candidate-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
        category: "network-attack",
        riskLevel: "High",
        filePath,
        lineStart: endpoint.line,
        lineEnd: endpoint.line,
        codeSnippet: endpoint.snippet,
        explanation: `Internal network endpoint detected. Potential SSRF if URL is user-controlled.`,
        recommendedFix: "Validate and allowlist destination URLs; block internal/private IP ranges.",
        evidenceTags: ["ssrf-candidate", "internal-endpoint"],
        confidence: "Medium",
        attackVector: "User-controlled URL → internal fetch → SSRF",
        reproductionSteps: ["Identify URL input", "Test internal IPs", "Test metadata endpoints"],
        disproofAttempts: ["Check URL validation", "Verify allowlist", "Test blocklist"]
      });
    }
  }

  return findings;
}

async function huntCryptoSecrets(filePath: string, targetDir: string): Promise<CandidateFinding[]> {
  const findings: CandidateFinding[] = [];
  if (!targetDir) return findings;

  let content: string;
  try {
    content = await fs.readFile(path.join(targetDir, filePath), "utf8");
  } catch {
    return findings;
  }

  const secretPatterns = [
    { pattern: /(?:api[_-]?key|secret|password|token|private[_-]?key)["']?\s*[:=]\s*["'][^"']{8,}/gi, type: "hardcoded-secret" },
    { pattern: /Math\.random\(\)/g, type: "weak-random" },
    { pattern: /crypto\.createHash\(['"]md5['"]\)/g, type: "weak-hash" },
    { pattern: /crypto\.createHash\(['"]sha1['"]\)/g, type: "weak-hash" },
    { pattern: /\b\w*(?:secret|token|apikey|api_key|password|passwd)\w*\s*==+\s*["']?[\w-]+/gi, type: "timing-attack" },
  ];

  for (const { pattern, type } of secretPatterns) {
    const matches = content.matchAll(pattern);
    for (const match of matches) {
      const lineNum = content.substring(0, match.index).split("\n").length;
      findings.push({
        id: `candidate-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
        category: "credential-leakage",
        riskLevel: type === "hardcoded-secret" ? "Critical" : type === "weak-random" ? "High" : "Medium",
        filePath,
        lineStart: lineNum,
        lineEnd: lineNum,
        codeSnippet: match[0].substring(0, 100),
        explanation: `Potential ${type} detected: ${match[0].substring(0, 50)}...`,
        recommendedFix: type === "hardcoded-secret" ? "Move secrets to environment variables or secret manager" :
                       type === "weak-random" ? "Use crypto.randomBytes or Web Crypto API" :
                       type === "weak-hash" ? "Use SHA-256 or stronger" :
                       "Use constant-time comparison (crypto.timingSafeEqual)",
        evidenceTags: [type, "crypto-candidate"],
        confidence: type === "hardcoded-secret" ? "High" : "Medium",
        attackVector: type === "hardcoded-secret" ? "Secret in code → repo exposure → credential theft" :
                      type === "weak-random" ? "Predictable tokens → session hijacking" :
                      "Timing side-channel → secret extraction",
        reproductionSteps: ["Locate secret/weak crypto", "Verify exploitability", "Assess impact"],
        disproofAttempts: ["Check if test/fixture", "Verify runtime usage", "Confirm constant-time"]
      });
    }
  }

  return findings;
}

function huntElectronIpc(filePath: string, inventory: ProjectInventory): CandidateFinding[] {
  const findings: CandidateFinding[] = [];

  if (inventory.electronIpcFiles.includes(filePath)) {
    findings.push({
      id: `candidate-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
      category: "electron-ipc",
      riskLevel: "High",
      filePath,
      lineStart: 1,
      lineEnd: 1,
      codeSnippet: "Electron IPC configuration file",
      explanation: "Electron IPC file detected. Verify contextIsolation, nodeIntegration, and contextBridge exposure.",
      recommendedFix: "Enable contextIsolation, disable nodeIntegration, validate all IPC messages, use strong CSP.",
      evidenceTags: ["electron-ipc", "ipc-config"],
      confidence: "Medium",
      attackVector: "Renderer compromise → IPC abuse → Node.js access → RCE",
      reproductionSteps: ["Check webPreferences", "Audit preload script", "Test IPC message validation", "Verify CSP"],
      disproofAttempts: ["Confirm contextIsolation=true", "Verify nodeIntegration=false", "Audit contextBridge exports"]
    });
  }

  return findings;
}

function huntSupplyChain(filePath: string, inventory: ProjectInventory): CandidateFinding[] {
  const findings: CandidateFinding[] = [];

  if (filePath === "package.json") {
    for (const dep of inventory.dependencySources) {
      findings.push({
        id: `candidate-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
        category: "supply-chain",
        riskLevel: dep.source.startsWith("file:") ? "Medium" : "High",
        filePath,
        lineStart: 1,
        lineEnd: 1,
        codeSnippet: dep.source,
        explanation: `Unpinned/remote dependency source: ${dep.source}`,
        recommendedFix: "Pin to exact registry version; verify lockfile integrity; use npm audit.",
        evidenceTags: ["supply-chain", "unpinned-dependency"],
        confidence: "High",
        attackVector: "Unpinned dependency → malicious publish → supply chain compromise",
        reproductionSteps: ["Identify unpinned dep", "Check for malicious versions", "Verify lockfile"],
        disproofAttempts: ["Confirm pinned version", "Verify registry source", "Check lockfile match"]
      });
    }
  }

  if (filePath.startsWith(".github/workflows/")) {
    findings.push({
      id: `candidate-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
      category: "github-actions",
      riskLevel: "Medium",
      filePath,
      lineStart: 1,
      lineEnd: 1,
      codeSnippet: "GitHub Actions workflow",
      explanation: "GitHub Actions workflow detected. Check for pull_request_target, unpinned actions, secret exposure.",
      recommendedFix: "Avoid pull_request_target; pin actions to full SHA; restrict secret permissions.",
      evidenceTags: ["supply-chain", "github-actions"],
      confidence: "Medium",
      attackVector: "Fork PR → pull_request_target → secret exfiltration / unpinned action → supply chain",
      reproductionSteps: ["Check trigger", "Verify action pins", "Audit secret permissions"],
      disproofAttempts: ["Confirm no pull_request_target", "Verify all SHA pins", "Check secret scopes"]
    });
  }

  return findings;
}

function updateCoverageLedgerFromHunter(ledger: CoverageLedger, result: HunterResult): CoverageLedger {
  const unit = ledger.units.find(u => u.id === result.unitId);
  if (!unit) return ledger;

  const status = result.candidates.length > 0 ? "covered" : "gap-detected";
  const findings = result.candidates.map(c => `${c.category}:${c.filePath}:${c.lineStart}`);

  return {
    ...ledger,
    units: ledger.units.map(u => u.id === result.unitId ? {
      ...u,
      status,
      findings: [...new Set([...u.findings, ...findings])],
      assignedHunter: result.hunterName,
      completedAt: new Date().toISOString()
    } : u),
    lastUpdated: new Date().toISOString()
  };
}

export function runCoverageCritic(ledger: CoverageLedger, architecture: ArchitectureSummary): CoverageUnit[] {
  const gaps: CoverageUnit[] = [];

  for (const unit of ledger.units) {
    if (unit.status === "unexplored") {
      gaps.push({ ...unit, status: "gap-detected" });
    } else if (unit.status === "covered" && unit.findings.length === 0) {
      gaps.push({ ...unit, status: "gap-detected" });
    }
  }

  return gaps;
}