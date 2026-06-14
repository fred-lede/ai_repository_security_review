# Repository Security Auditor

A multi-layered security analysis tool that detects suspicious behavior in repositories, npm packages, and source code. Combines **deterministic static analysis** (suspicious patterns, data flow tracing) with an **optional AI review layer** for human-readable assessment.

```sh
npm run dev:cli -- scan ./fixtures/malicious-package
```

## Features

- **Multi-target scanning** — Local directories, files, archives, GitHub repositories (cloned on-the-fly)
- **~30 built-in detection rules** — Postinstall scripts, unpinned dependencies, command injection, network exfiltration, credential leakage, persistence mechanisms, Electron IPC risks, GitHub Actions abuse
- **Data flow graph** — Traces sensitive sources (env vars, filesystem) through processes to external sinks
- **Risk assessment** — Block/Needs Review/Monitor/Pass decisions with residual risk analysis
- **4 output formats** — Markdown (readable report), JSON (full data), Mermaid (flowchart), SARIF (IDE integration)
- **AI review** — Optional Ollama/OpenAI integration with configurable data-sharing modes and secret redaction
- **Desktop app** — Electron GUI for point-and-click scanning with language switching and custom rules editor
- **Extensible rules** — Write custom rules as JSON; rules load from a file and merge with built-in rules at scan time
- **i18n** — English, Traditional Chinese, Simplified Chinese
- **Secure** — OS-level encrypted API key storage (macOS Keychain / Windows DPAPI / Linux libsecret), path traversal prevention in archives, safe IPC allowlist

## Quick Start

```bash
# Install
npm install

# Build all packages
npm run build

# CLI — scan a malicious test fixture
npm run dev:cli -- scan fixtures/malicious-package

# CLI — scan a remote GitHub repo
npm run dev:cli -- scan https://github.com/user/repo

# Desktop app
npm run dev:electron
```

## CLI Usage

```text
Usage: repo-auditor scan [options] <target>

Arguments:
  target                    Local directory, file, archive, GitHub URL, or npm package

Options:
  --offline                 Reject remote acquisition
  --no-network              Reject remote acquisition
  --output <dir>            Output directory (default: "reports/latest")
  --format <formats>        Comma-separated output formats (default: "markdown,json,mermaid")
  -h, --help                Display help

Exit codes:
  0   Scan completed (decision: Pass / Monitor / Needs Review)
  2   Scan completed (decision: Block)
```

### Examples

```bash
# Scan a local directory
npm run dev:cli -- scan /path/to/project

# Scan a single file
npm run dev:cli -- scan /path/to/file.js

# Scan a GitHub repository (cloned automatically)
npm run dev:cli -- scan https://github.com/owner/repo

# Generate SARIF output only
npm run dev:cli -- scan /path/to/project --format sarif
```

## Desktop App

```bash
npm run dev:electron
```

The Electron app provides:
- Point-and-click target selection (directory, file, GitHub, npm)
- Language selector (EN / zh-TW / zh-CN)
- Network policy toggle (offline / online)
- AI provider configuration (Ollama, OpenAI, custom)
- Report preview with color-coded findings
- One-click export to all formats
- Built-in rules editor (Edit Rules button)
- OS-encrypted API key storage

### Package for distribution

```bash
npm run package:mac
npm run package:win
npm run package:linux
npm run package:all    # All three platforms
```

## Project Structure

```
├── apps/
│   └── electron/           # Desktop GUI (main + renderer)
│       ├── src/main.ts       # Electron main process
│       ├── src/preload.cjs   # Secure IPC bridge
│       └── src/renderer/     # HTML/CSS/JS UI
├── packages/
│   ├── scanner-core/        # Scanning engine
│   │   ├── src/rules.ts       # Rule engine (built-in + custom)
│   │   ├── src/inventory.ts   # Project inventory builder
│   │   ├── src/dataFlow.ts    # Data flow graph
│   │   ├── src/risk.ts        # Risk assessment
│   │   ├── src/reporters.ts   # Output renders (md/json/mermaid/sarif)
│   │   ├── src/ruleTypes.ts   # Declarative rule format
│   │   ├── src/defaultRules.ts# Built-in detection rules
│   │   └── src/i18n.ts        # Translation tables
│   ├── ai-review/           # AI-powered review layer
│   │   └── src/review.ts      # Prompt builder + provider integration
│   └── cli/                 # Command-line interface
├── fixtures/
│   ├── malicious-package/   # Suspicious test fixture
│   └── benign-package/      # Clean test fixture
└── docs/
    └── validation/          # Real-world validation results
```

## Detection Rules

### Built-in Rules

| Rule | Category | Detects |
|------|----------|---------|
| Postinstall script | `postinstall-script` | Lifecycle scripts (pre/postinstall, prepare, prepack) |
| Unpinned dependency | `supply-chain` | Git/HTTP/tarball/file dependency sources |
| Command execution | `command-injection` | Shell/process execution via exec/spawn/execFile |
| Network analysis | `network` | Outbound endpoints near sensitive sources (exfiltration candidates) |

### Custom Rules

Rules are declarative JSON. Create a `repo-auditor-rules.json` in the app data directory, or use the in-app **Edit Rules** button:

```json
[
  {
    "id": "detect-telemetry",
    "description": "Endpoints with 'telemetry' in the path",
    "category": "hidden-telemetry",
    "defaultRiskLevel": "Medium",
    "inventoryField": "networkEndpoints",
    "conditions": [
      { "field": "endpoint", "operator": "contains", "value": "telemetry" }
    ],
    "explanation": "Found a telemetry endpoint.",
    "recommendedFix": "Verify the endpoint is documented.",
    "tags": ["telemetry"]
  }
]
```

Supported condition operators: `equals`, `contains`, `matches` (regex), `in`, `not_in`.

## Finding Categories (15)

| Category | Risk |
|----------|------|
| `data-exfiltration` | Blocking |
| `credential-leakage` | Blocking |
| `command-injection` | Blocking |
| `remote-code-execution` | Blocking |
| `persistence` | Blocking |
| `postinstall-script` | Blocking |
| `github-actions` | Blocking |
| `hidden-telemetry` | Informational |
| `tracking` | Informational |
| `supply-chain` | Informational |
| `electron-ipc` | Informational |
| `network` | Informational |
| `filesystem` | Informational |
| `environment` | Informational |
| `database` | Informational |

## Output Formats

| Format | File | Use case |
|--------|------|----------|
| Markdown | `report.md` | Human-readable findings report |
| JSON | `findings.json` | Machine parsing / CI integration |
| Mermaid | `data-flow.mmd` | Data flow visualization |
| SARIF | `results.sarif` | IDE integration (VS Code, GitHub) |
| Decision | `decision-record.json` | Audit decision with rationale |
| Remediation | `remediation-list.json` | Categorized fix suggestions |

## AI Review

Supports any OpenAI-compatible API (including local Ollama instances):

```bash
# Via CLI (coming soon)
# In the desktop app: configure provider -> click "Prepare AI Review"
```

Data-sharing modes control how much context is sent:
- `metadata-only` — Finding IDs and categories only (no code)
- `finding-snippets` — With code snippets (secrets redacted)
- `full-files` — Full source files

Secret redaction automatically masks:
- Telegram bot tokens
- GitHub tokens
- OpenAI / AWS / generic API keys
- Any `secret`/`password`/`token`-named values

## Language Support

| Code | Language |
|------|----------|
| `en` | English |
| `zh-TW` | Traditional Chinese |
| `zh-CN` | Simplified Chinese |

Reports, decisions, risk assessments, AI prompts, and the desktop UI all respect the selected language.

## Development

```bash
# Build everything
npm run build

# Run all tests (79+ tests across 4 packages)
npm test

# Run specific package tests
npm --workspace packages/scanner-core test
npm --workspace packages/ai-review test
npm --workspace packages/cli test
npm --workspace apps/electron test

# Type-check all packages
npm run typecheck --workspaces --if-present
```

## Security

- **Context isolation** — Electron renderer has no Node.js access; all IPC is allowlisted
- **No arbitrary shell commands** — The scanner reads and parses code; it does not execute it
- **Safe archive extraction** — Rejects symlinks, absolute paths, path traversal, and device entries
- **OS-level encryption** — API keys are encrypted via `safeStorage` (macOS Keychain / Windows DPAPI / Linux libsecret)
- **Secret redaction** — AI review prompts are scanned for secrets before sending to external providers

## License

MIT
