# Repository Security Auditor Design

Date: 2026-06-14

## Goal

Build a cross-platform security audit tool for GitHub repositories, npm packages, and local source folders. The tool assumes a repository may be intentionally malicious and reports suspicious behavior with file-level evidence, code snippets, explanations, recommended fixes, and a complete data flow diagram.

The first real validation target is `grinev/opencode-telegram-bot`, a Node.js repository hosted on GitHub. Its public README describes a Telegram bot that runs locally, talks to the Telegram Bot API, communicates with a local OpenCode server, reads configuration from platform app-data paths, and supports file browsing and command-like operations. Those surfaces make it a useful first audit sample.

Source: https://github.com/grinev/opencode-telegram-bot

## Product Shape

Use a shared scanner engine with two user surfaces:

1. `scanner-core`: a Node.js/TypeScript library that performs all repository/package analysis and produces structured findings.
2. `cli`: a terminal and CI interface that calls `scanner-core` and exports Markdown, JSON, SARIF, and Mermaid diagrams.
3. `electron-app`: a cross-platform desktop application for macOS, Windows, and Ubuntu that uses the same scanner engine and presents findings, snippets, and data flow diagrams.
4. `ai-review`: an optional review layer that summarizes deterministic findings, explains risk, and suggests fixes through a user-selected provider.

This keeps the analysis engine usable in automation while still supporting a packaged desktop experience.

## Architecture

The tool has four main layers:

1. Target acquisition
   - Accept a GitHub repository URL, npm package name, tarball URL, or local directory.
   - Accept single files and archive files for focused review.
   - Clone or download into an isolated temporary workspace.
   - Avoid running package scripts during acquisition.
   - Record provenance: source URL, commit SHA or package version, lockfile hashes, and scan timestamp.

2. Scanner core
   - Parse project metadata such as `package.json`, lockfiles, GitHub Actions workflows, TypeScript/JavaScript files, shell scripts, Docker files, and Electron files.
   - Build findings from deterministic rule packs.
   - Build a data flow graph from sources to local sinks and external destinations.
   - Produce stable JSON output for CLI, UI, and CI use.

3. AI review layer
   - Runs only after deterministic findings and data flow evidence are generated.
   - Never creates findings without linking back to scanner evidence.
   - Supports provider profiles:
     - Cloud model provider selected by the user.
     - Local Ollama provider.
     - Custom OpenAI-compatible HTTP provider.
   - Lets the user choose what leaves the machine:
     - Finding metadata only.
     - Snippets referenced by findings.
     - Full files, disabled by default.
   - Redacts detected secrets before any cloud or custom provider request.
   - Records provider, model, redaction mode, prompt template version, and timestamp in the report provenance.

4. CLI
   - Commands:
     - `scan <target>`
     - `scan-github <repo-url>`
     - `scan-npm <package>`
     - `scan-local <path>`
     - `scan-file <path>`
     - `ai-review <report-path>`
     - `export <scan-id>`
   - Output formats:
     - Markdown report for human review.
     - JSON for Electron and integrations.
     - SARIF for GitHub code scanning.
     - Mermaid for data flow diagrams.
     - Patch plan output for optional remediation workflows.

5. Electron app
   - Renderer displays target selection, scan progress, finding table, code snippets, risk filters, and data flow diagram.
   - Renderer displays AI provider settings and explicit data-sharing controls.
   - Main process owns filesystem, process, and network access.
   - IPC is allowlisted and narrow: start scan, cancel scan, run AI review, read report, export report, open report folder.
   - Renderer does not receive Node integration, arbitrary filesystem access, raw shell access, or unrestricted URL fetch capability.

## Security Model For The Auditor

The auditor itself must be designed as if target repositories are hostile.

- Never run `npm install`, `npm test`, `postinstall`, `prepare`, or arbitrary repository scripts during scanning.
- Parse files statically where possible.
- Unpack npm tarballs into isolated temporary directories.
- Treat repository files, package manifests, workflows, and README content as untrusted input.
- Do not execute target code.
- Avoid rendering untrusted Markdown or HTML without sanitization.
- Sanitize code snippets before displaying them in Electron.
- Keep Electron `contextIsolation` enabled.
- Keep `nodeIntegration` disabled in the renderer.
- Expose only typed, allowlisted IPC methods from preload.
- Avoid automatic update checks in MVP unless explicitly enabled and visible in settings.
- Make AI review opt-in.
- Do not send source code, snippets, environment values, file paths, or findings to a cloud or custom provider unless the user explicitly enables that provider and confirms the selected data-sharing mode.
- Always redact detected secrets before AI review requests, including local Ollama requests, so provider switching cannot accidentally weaken privacy.
- Store AI provider credentials in the platform credential store where available, not in project reports.

## Target Input Model

All input modes flow through a shared Target Resolver used by both CLI and Electron.

Supported target types:

- Local directory
  - CLI: `scan-local /path/to/project` or `scan /path/to/project`
  - Electron: choose folder
  - Network required: no
  - Scope: scans all supported files under the directory while respecting ignore rules.

- Single local file
  - CLI: `scan-file /path/to/file.js` or `scan /path/to/file.js`
  - Electron: choose file
  - Network required: no
  - Scope: focused scan for secrets, network calls, command execution, env access, filesystem access, and suspicious code patterns. Data flow is file-scoped.

- Archive file
  - CLI: `scan-file /path/to/source.zip` or `scan /path/to/source.tgz`
  - Electron: choose archive
  - Network required: no
  - Scope: extracts into an isolated temporary directory and scans like a local directory. Supported archive types for MVP are `.zip`, `.tgz`, and `.tar.gz`.

- GitHub repository
  - CLI: `scan-github https://github.com/owner/repo.git` or `scan https://github.com/owner/repo`
  - Electron: paste GitHub URL
  - Network required: yes
  - Scope: clone or download without running repository code. Records URL, default branch, commit SHA, and scan timestamp. Optional branch, tag, or commit can be added later.

- npm package
  - CLI: `scan-npm package-name` or `scan-npm package-name@version`
  - Electron: enter npm package spec
  - Network required: yes
  - Scope: fetch package metadata and tarball from the configured registry, unpack without running lifecycle scripts, and scan package contents plus package metadata.

- npm tarball URL
  - CLI: `scan https://registry.npmjs.org/name/-/name-version.tgz`
  - Electron: paste tarball URL
  - Network required: yes
  - Scope: download tarball, record source URL and digest, unpack into an isolated temporary directory, and scan package contents.

- Generic remote archive URL
  - CLI: `scan https://example.com/source.zip`
  - Electron: paste archive URL
  - Network required: yes
  - Scope: download only if the user confirms the destination and file type. Record URL, digest, and timestamp. This mode is lower priority than GitHub and npm in MVP.

Input normalization:

- Every target becomes a `ResolvedTarget` with `type`, `source`, `localPath`, `provenance`, `networkUsed`, and `trustBoundary`.
- Remote targets are copied into an isolated scan workspace.
- Local targets are scanned read-only by default.
- Archive extraction must prevent path traversal and symlink escape.
- The scanner never executes target code during acquisition or analysis.

Electron input UI:

- First screen offers four input cards: Local Folder, File or Archive, GitHub Repository, npm Package.
- Advanced input allows tarball URL, generic archive URL, custom npm registry, and local report import.
- For any mode that uses network, the UI shows what will be fetched before starting.
- For any mode that can send data to an AI provider, the UI shows the selected AI data-sharing mode before running AI review.

CLI input behavior:

- `scan <target>` auto-detects target type from path, URL, or npm package-like spec.
- Specific commands such as `scan-github`, `scan-npm`, `scan-local`, and `scan-file` bypass auto-detection for predictable automation.
- `--no-network` rejects GitHub, npm, and remote URL targets.
- `--offline` scans only local directories, files, archives, or previously downloaded scan workspaces.
- `--output <dir>` controls report location.
- `--format markdown,json,sarif,mermaid` controls export formats.

## End-To-End Audit Workflow

The tool should guide users through a complete security review process from target input to final decision. The workflow must be the same conceptually across CLI, Electron, and CI, with different presentation layers.

### Phase 1: Intake

Goal: capture what is being reviewed and what the user expects from the review.

Inputs:

- Target type: local folder, file, archive, GitHub repository, npm package, npm tarball URL, or generic remote archive URL.
- Review mode:
  - quick triage: fast scan for high-risk indicators.
  - full audit: all rule packs, full data flow, full report.
  - CI gate: machine-readable output and non-zero exit code on configured severity threshold.
- Network policy:
  - online.
  - `--no-network`.
  - offline.
- AI review setting:
  - disabled.
  - Ollama.
  - cloud provider.
  - custom OpenAI-compatible provider.
- Data-sharing mode for AI review.
- Output directory and export formats.

User-facing result:

- A pre-scan summary showing what will be read, what will be downloaded, whether network is required, and whether any data may be sent to an AI provider.

### Phase 2: Safe Target Acquisition

Goal: obtain the target without executing untrusted code.

Actions:

- Resolve the target with the Target Resolver.
- Download or clone remote targets into an isolated scan workspace.
- Copy or reference local targets in read-only mode.
- Extract archives with path traversal and symlink escape protections.
- Record provenance: URL, commit SHA, package version, digest, timestamp, registry, and acquisition network use.
- Refuse or warn on unsupported file types, excessive archive size, nested archive depth, or suspicious extraction paths.

User-facing result:

- Acquisition status, resolved target identity, provenance, and warnings before analysis starts.

### Phase 3: Project Inventory

Goal: build a factual inventory before judging risk.

Actions:

- Detect languages and frameworks.
- Detect package managers and lockfiles.
- Parse `package.json`, npm lockfiles, GitHub Actions workflows, Docker files, shell scripts, TypeScript/JavaScript, Electron files, and config files.
- Build inventories for:
  - scripts and lifecycle hooks.
  - dependencies and dependency sources.
  - environment variables.
  - filesystem access.
  - network endpoints.
  - command execution APIs.
  - persistence surfaces.
  - CI/CD permissions.
  - Electron IPC surfaces.

User-facing result:

- Inventory summary with counts and high-signal surfaces, even when no high-risk finding is confirmed.

### Phase 4: Static Security Analysis

Goal: identify suspicious behavior with deterministic evidence.

Actions:

- Run rule packs for data exfiltration, credential leakage, telemetry/tracking, RCE, command injection, supply chain risk, postinstall scripts, GitHub Actions abuse, Electron IPC abuse, persistence, network communication, filesystem access, database access, and environment access.
- Extract code snippets with line numbers.
- Attach confidence and evidence tags to each finding.
- Avoid executing target code.

User-facing result:

- Initial finding list sorted by severity and confidence.

### Phase 5: Data Flow Modeling

Goal: explain how data moves through the project.

Actions:

- Build source, transformation, sink, and destination nodes.
- Link findings to data-flow edges.
- Highlight outbound flows leaving the machine.
- Separate audited-project traffic from auditor-originated traffic such as AI provider requests.
- Mark local-only flows, expected external APIs, unknown external APIs, and exfiltration candidates.

User-facing result:

- Mermaid diagram, interactive Electron diagram, and machine-readable data-flow graph.

### Phase 6: Optional AI Review

Goal: improve reviewer understanding without replacing deterministic evidence.

Actions:

- Redact secrets before provider requests.
- Send only the selected data-sharing level.
- Ask the selected provider to summarize risk, explain evidence, suggest safer patterns, and flag possible false positives.
- Link every AI comment back to scanner findings.
- Record provider, model, endpoint type, prompt template version, redaction mode, and timestamp.

User-facing result:

- AI review section clearly marked as assistant-generated analysis, not ground truth.

### Phase 7: Risk Assessment

Goal: turn evidence into a practical decision.

Actions:

- Compute overall risk from severity, confidence, exploitability, affected data, outbound destinations, install-time behavior, and execution surface.
- Produce a risk matrix by category, file, data flow, and severity.
- Identify top risks and likely business impact.
- Mark expected behavior separately from suspicious behavior, especially for packages that legitimately communicate with APIs.

Decision labels:

- `Block`: critical or high-confidence high-risk behavior that can expose secrets, execute commands, persist, or exfiltrate sensitive data.
- `Needs Review`: suspicious or medium-confidence high-impact behavior requiring maintainer explanation.
- `Monitor`: low-risk or expected external behavior that should be documented or controlled.
- `Pass`: no material risky behavior found within scanner limits.

User-facing result:

- A clear recommendation with evidence and uncertainty.

### Phase 8: Remediation Planning

Goal: help the user decide what to fix and how.

Actions:

- Prioritize fixes by risk and ease of remediation.
- Provide concrete recommended changes.
- Suggest safer APIs or patterns.
- Suggest tests and verification commands.
- Estimate breaking-change risk.
- Generate optional patch drafts only when the change is deterministic and local.

User-facing result:

- Remediation plan suitable for a maintainer ticket, pull request plan, or internal security review.

### Phase 9: Export And Decision Record

Goal: make the result shareable and auditable.

Actions:

- Export Markdown, JSON, SARIF, Mermaid, and remediation plan.
- Include provenance, tool version, rule pack version, AI provider metadata if used, and scan limitations.
- Allow CI mode to fail builds based on configured severity threshold.
- Allow Electron users to export a report bundle.

User-facing result:

- A complete decision package that can support accept, block, escalate, or remediate decisions.

### Phase 10: Verification And Re-Scan

Goal: verify fixes and compare risk over time.

Actions:

- Re-run scan after patches or upstream updates.
- Compare new report against prior report.
- Show fixed, new, and unchanged findings.
- Confirm patch verification only when evidence supports it.

User-facing result:

- Delta report for maintainers and reviewers.

## Rule Packs

### Data Exfiltration

Detect flows where sensitive sources reach outbound destinations.

Sources:
- `process.env`
- `.env` and config files
- tokens, API keys, passwords, cookies, session IDs
- local files
- git metadata
- user-provided prompts or attachments
- project paths and filenames

Outbound sinks:
- `fetch`
- `axios`
- `http.request`
- `https.request`
- WebSocket clients
- Telegram Bot API calls
- webhook calls
- analytics or tracking SDKs
- custom API domains

### Credential Leakage

Detect:
- hardcoded token-like strings
- secret regex matches
- credentials logged to console or files
- credentials sent to external domains
- `.env` files accidentally committed
- GitHub Actions secrets exposed to untrusted contexts

### Hidden Telemetry And Tracking

Detect:
- analytics SDK imports
- event tracking calls
- machine/user identifiers sent over the network
- external domains unrelated to the package purpose
- opt-out missing for telemetry-like behavior

### Remote Code Execution And Command Injection

Detect:
- `child_process.exec`
- shell command string interpolation
- `spawn` or `execFile` with untrusted arguments
- `eval`
- `new Function`
- dynamic imports from computed or remote paths
- remote script download and execution

### Supply Chain And Postinstall

Detect:
- `preinstall`, `install`, `postinstall`, `prepare`, `prepack`, `postpack`
- git dependencies
- tarball dependencies
- local file dependencies
- suspicious package aliases
- lockfile package source drift
- lifecycle scripts that access network, shell, filesystem, or secrets

### GitHub Actions Abuse

Detect:
- `pull_request_target`
- broad `permissions: write-all`
- unchecked use of secrets
- shell execution of remote content
- `curl | bash`
- dependency install with lifecycle scripts enabled
- workflow dispatch or scheduled jobs with dangerous permissions

### Electron IPC Abuse

Detect in audited repositories:
- `nodeIntegration: true`
- `contextIsolation: false`
- overly broad preload APIs
- `ipcMain.on` or `ipcMain.handle` that executes arbitrary commands
- file reads or writes from renderer-controlled paths
- unrestricted `shell.openExternal`
- unsafe URL navigation

### Persistence Mechanisms

Detect:
- launch agents
- systemd unit creation
- cron writes
- Windows startup folders or registry run keys
- daemon/service installation
- background process managers

### Network Communication

Extract and classify:
- external domains
- local endpoints
- API paths
- custom headers
- proxy configuration
- file download endpoints
- upload endpoints

All data leaving the machine is highlighted in the data flow diagram and report.

AI review network calls are also highlighted. Cloud and custom-provider calls are treated as data leaving the machine. Ollama calls to `localhost` are treated as local by default, but the report still records the endpoint.

### Filesystem, Database, And Environment Access

Detect:
- `fs.readFile`, `fs.writeFile`, streams, directory traversal
- platform app-data paths
- attachment handling
- local database clients such as SQLite, PostgreSQL, MongoDB, Redis
- `process.env` reads and writes

## Finding Schema

Each finding includes:

- `riskLevel`: `Critical`, `High`, `Medium`, `Low`, or `Info`
- `category`: one of the rule pack categories
- `filePath`
- `lineStart`
- `lineEnd`
- `codeSnippet`
- `explanation`
- `recommendedFix`
- `evidenceTags`
- `source`
- `sink`
- `dataFlowId`
- `confidence`: `High`, `Medium`, or `Low`
- `aiReview`: optional provider-generated explanation, false-positive notes, and fix guidance linked to deterministic evidence
- `remediation`: structured recommended change, affected API, test suggestion, and optional patch draft

Markdown report fields:

```text
Risk Level
File Path
Code Snippet
Explanation
Recommended Fix
```

## Audit Report Contract

The audit output must be comprehensive and useful for both security reviewers and maintainers. Every report contains these sections:

1. Executive summary
   - Overall risk level.
   - Short explanation of the risk posture.
   - Top three risks.
   - Whether any data appears to leave the machine.
   - Whether any credentials, tokens, or local files may be exposed.
   - Whether any commands may be executed from untrusted input.

2. Scope and provenance
   - Target type and source.
   - Local scan path or isolated workspace path.
   - Commit SHA, package version, tarball digest, or file digest when available.
   - Scan timestamp.
   - Network used during acquisition.
   - AI provider used, if any, including data-sharing mode and redaction mode.

3. Risk matrix
   - Count by severity.
   - Count by category.
   - Highest-risk data flows.
   - Highest-risk files.
   - Confidence distribution.

4. Findings
   - Full finding list with risk level, file path, code snippet, explanation, recommended fix, evidence tags, confidence, and data flow link.
   - Findings sorted by severity, then confidence, then file path.
   - False-positive notes only if supported by evidence or clearly marked as AI opinion.

5. Data flow diagram
   - Sources, transformations, APIs, file system access, environment access, database access, local sinks, and external destinations.
   - All data leaving the machine highlighted.
   - Tool-originated AI provider traffic visually separated from audited-repository behavior.

6. External communication inventory
   - Domains.
   - URLs or API roots.
   - Protocols.
   - HTTP methods when detectable.
   - Headers that may carry credentials.
   - Source file and line reference.
   - Classification: expected, suspicious, tracking, exfiltration candidate, or unknown.

7. Sensitive data inventory
   - Environment variables.
   - Config files.
   - Credential-like strings.
   - Local file reads.
   - User input, attachments, prompts, or project metadata used in outbound flows.

8. Execution and persistence inventory
   - Command execution APIs.
   - Shell interpolation.
   - Lifecycle scripts.
   - GitHub Actions execution surfaces.
   - Service, daemon, startup, cron, launch agent, or systemd behavior.

9. Remediation plan
   - Prioritized fix list.
   - Recommended owner action for each finding.
   - Safer implementation pattern.
   - Suggested tests or verification steps.
   - Breaking-change risk.
   - Optional patch draft when the change is local and deterministic.

10. Maintainer checklist
   - Remove or gate unnecessary network calls.
   - Redact secrets from logs and outbound payloads.
   - Replace shell execution with safe argument arrays.
   - Disable install lifecycle side effects unless essential.
   - Reduce GitHub Actions permissions.
   - Harden Electron IPC if applicable.
   - Add tests for security-sensitive paths.

11. Machine-readable attachments
   - `findings.json`
   - `data-flow.mmd`
   - `report.md`
   - `report.sarif`
   - `remediation-plan.json`
   - `decision-record.json`

Report requirements:

- Do not make unsupported claims. If evidence is weak, lower confidence instead of inflating severity.
- Do not hide low-confidence issues when they involve credentials, command execution, persistence, or outbound network traffic.
- Do not mark a finding as fixed unless a patch is applied and tests or verification support it.
- Recommended fixes must be concrete enough for a maintainer to act on.
- Patch drafts must be opt-in and generated separately from the audit verdict.

## Decision Output

The final report must help users make a decision, not only inspect raw evidence.

Decision states:

- `Block`: do not install, run, merge, or approve until fixed. Used when evidence shows likely credential exposure, data exfiltration, command execution from untrusted input, install-time execution risk, persistence, or unsafe privileged automation.
- `Needs Review`: escalate to a human reviewer or maintainer. Used when behavior may be legitimate but requires explanation, documentation, configuration changes, or tighter controls.
- `Monitor`: acceptable with follow-up. Used for expected network communication, low-risk telemetry, broad but documented filesystem access, or patterns that should be watched over time.
- `Pass`: no material risk found within the configured scan scope and scanner limitations.

Decision record fields:

- `decision`
- `overallRiskLevel`
- `rationale`
- `blockingFindings`
- `requiredFixes`
- `recommendedFixes`
- `acceptedRisks`
- `residualRisk`
- `scanLimitations`
- `reviewerNotes`
- `generatedAt`

Decision rules:

- Any `Critical` finding defaults to `Block`.
- Any high-confidence `High` finding involving secrets, outbound data, command execution, persistence, install lifecycle scripts, or CI secret exposure defaults to `Block`.
- Medium-confidence high-impact findings default to `Needs Review`.
- Expected external API use can be `Monitor` or `Pass` only when the report shows why it is expected and what data is sent.
- AI review may explain or recommend, but it cannot lower a deterministic `Block` decision by itself.
- Users may manually override the final decision in Electron, but the report must preserve the original scanner recommendation and the override reason.

## Data Flow Diagram

The diagram shows:

- Sources
- Internal processing
- APIs
- External domains
- Database access
- File system access
- Environment variable access
- Local destinations
- External destinations
- AI review provider endpoints

Diagram convention:

- Sources are shown on the left.
- Internal processing is shown in the middle.
- Local sinks are shown below the processing nodes.
- External destinations are shown on the right.
- All data leaving the machine is highlighted.
- AI provider calls are visually distinct from audited-repository behavior so users can separate tool-originated traffic from target-originated traffic.

The CLI exports Mermaid syntax. The Electron app renders the same graph interactively and links graph edges back to findings.

## Risk Scoring

Default severity:

- `Critical`: confirmed secret or sensitive local data flows to an external destination; command execution from untrusted input; malicious install script that executes remote code.
- `High`: likely exfiltration path, broad RCE primitive, dangerous GitHub Actions secret exposure, unsafe Electron IPC command or file bridge.
- `Medium`: suspicious network behavior, lifecycle script with filesystem/network access, risky dependency source, broad filesystem access.
- `Low`: weak indicators, unusual configuration, telemetry without clear sensitivity.
- `Info`: expected behavior that should be reviewed, such as documented Telegram API usage.

Confidence is separate from severity. A high-severity finding can have medium confidence if static analysis cannot prove the full flow.

## MVP Validation Target

Use `https://github.com/grinev/opencode-telegram-bot.git` as the first audit target.

The validation report must include:

- package script review
- dependency and lockfile review
- GitHub Actions review
- environment variable map
- network destination map
- filesystem access map
- command execution review
- data flow diagram highlighting outbound communication
- recommendations for each finding
- optional AI review using a local Ollama provider or a user-configured provider, with the selected data-sharing mode recorded

## Repository Layout

Use a TypeScript monorepo:

- `packages/scanner-core`: parsers, rule packs, finding model, data flow graph, report serializers.
- `packages/cli`: command-line interface that depends on `scanner-core`.
- `packages/ai-review`: provider adapters, prompt templates, redaction, and AI review result schema.
- `apps/electron`: desktop application that depends on `scanner-core` and reads scan reports through typed IPC.
- `fixtures`: intentionally malicious and benign sample projects used by tests.

## AI Review Providers

The AI review feature is optional and provider-neutral.

Provider types:

- `cloud`: user-configured cloud model provider. The MVP should avoid hardcoding a single model name; users provide provider settings and model ID.
- `ollama`: local Ollama endpoint, defaulting to `http://localhost:11434`.
- `custom`: custom OpenAI-compatible provider with base URL, model ID, and optional API key.

Provider configuration:

- Provider type.
- Base URL.
- Model ID.
- API key or token reference.
- Data-sharing mode.
- Redaction enabled flag, on by default and required for cloud/custom providers.
- Request timeout and retry limit.

Supported AI tasks:

- Summarize the overall audit risk.
- Explain why deterministic findings matter.
- Suggest safer code patterns.
- Identify likely false positives, clearly marked as AI opinion.
- Produce an executive summary for the Markdown report.

AI review must not:

- Create ungrounded findings.
- Hide or downgrade deterministic findings.
- Send data to a provider without explicit user configuration.
- Store provider API keys in exported reports.

## Packaging

Use `electron-builder` for desktop packaging and produce installers for:

- macOS
- Windows
- Ubuntu/Linux

The scanner core and CLI should remain usable without Electron. The desktop app should bundle the scanner and expose export options for Markdown, JSON, SARIF, and Mermaid.

Package scripts should support:

- `npm run build`
- `npm run test`
- `npm run package:mac`
- `npm run package:win`
- `npm run package:linux`
- `npm run package:all`

## Testing Strategy

Tests should cover:

- rule matching on small malicious fixtures
- parser behavior on malformed files
- package script detection
- GitHub Actions detection
- Electron IPC detection
- data flow graph generation
- report serialization
- CLI scan of a local fixture
- AI provider configuration validation
- redaction before AI requests
- Ollama provider request construction
- custom provider request construction
- AI review output linked to deterministic findings

The first end-to-end test uses a local fixture. The first real-world validation uses `grinev/opencode-telegram-bot`.

## Out Of Scope For MVP

- Dynamic sandbox execution of malicious packages
- Full interprocedural taint analysis across all JavaScript patterns
- Automatic remediation PRs
- Cloud-hosted scanning service
- Background telemetry from the auditor itself
- AI-only scanning without deterministic evidence
