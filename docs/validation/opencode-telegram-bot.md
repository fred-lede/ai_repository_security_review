# opencode-telegram-bot Validation Notes

Target: https://github.com/grinev/opencode-telegram-bot.git

Validation date: 2026-06-14

Acquisition:

- Command: `git clone --depth 1 https://github.com/grinev/opencode-telegram-bot.git scan-workspaces/opencode-telegram-bot`
- Safety posture: source-only shallow clone; no dependency install; no package scripts; no target code execution.

Scan:

- Command: `node packages/cli/dist/index.js scan scan-workspaces/opencode-telegram-bot --offline --format markdown,json,mermaid,sarif --output reports/opencode-telegram-bot`
- Network policy: `offline`
- Generated outputs:
  - `reports/opencode-telegram-bot/report.md`
  - `reports/opencode-telegram-bot/findings.json`
  - `reports/opencode-telegram-bot/data-flow.mmd`
  - `reports/opencode-telegram-bot/results.sarif`
  - `reports/opencode-telegram-bot/decision-record.json`
  - `reports/opencode-telegram-bot/remediation-list.json`

## Decision Summary

- Overall risk: High
- Decision: Block
- Total findings: 116
- Severity counts: High 3, Medium 9, Low 104
- Category counts: command-injection 3, network 113
- Blocking findings: `finding-1`, `finding-2`, `finding-3`

## Blocking Findings

| Risk | File | Evidence | Recommended decision |
| --- | --- | --- | --- |
| High | `src/opencode/process.ts:62` | `spawn(spawnCommand.command, spawnCommand.args, {` | Review whether `spawnCommand.command` and args can be user-controlled. Require allowlisted command names and explicit argument arrays before trust. |
| High | `src/app/services/worktree-service.ts:73` | `execFile(` | Review caller-controlled inputs and working directory handling. Keep `execFile` arguments fully structured and reject shell interpolation. |
| High | `src/runtime/service/manager.ts:212` | `spawn(process.execPath, childArgs, {` | Review `childArgs` construction and runtime persistence behavior. Confirm no untrusted input can alter executable path, arguments, or environment. |

## External Communication Findings

Medium-risk external endpoints were detected in workflow/package metadata, release tooling, Telegram file download defaults, and model documentation links. Examples:

- `.github/workflows/publish.yml:33` -> `https://registry.npmjs.org`
- `scripts/generate-release-notes.mjs:146` -> `https://api.github.com/repos/${repository}/pulls/${prNumber}`
- `src/app/services/file-download-service.ts:9` -> `https://api.telegram.org`
- `src/app/services/scheduled-task-executor-service.ts:17` -> `https://opencode.ai/docs/config/#models`

Low-risk network findings mostly came from tests, examples, localhost defaults, and documentation-style URLs. These are retained for transparency but do not block the decision.

## Data Flow Notes

The generated Mermaid graph highlights all known external destinations with `leavesMachine: true`. It includes:

- Sources: environment variables such as `GITHUB_TOKEN`, `TELEGRAM_PROXY_SECRET`, `TELEGRAM_PROXY_URL`, `GOOGLE_APPLICATION_CREDENTIALS`, and local filesystem reads.
- APIs/processes: network endpoints, process execution APIs, and command/process launch sites.
- Destinations: GitHub, npm registry, Telegram API, OpenAI/Groq/ElevenLabs-style endpoints referenced by source or tests, localhost defaults, and example domains.

## Validation Outcome

This target should remain blocked until a human reviewer confirms the three process execution findings are intended and properly constrained. No deterministic evidence of confirmed credential exfiltration was produced by this static scan, but the presence of command/process execution in a bot automation project is high-impact enough to require manual review.

## Scanner Tuning Found During Validation

Validation revealed two scanner quality issues and both were fixed before producing this note:

- Lockfile tarball URLs were initially treated as runtime network traffic; they are now excluded from runtime network inventory.
- `RegExp.prototype.exec(...)` was initially treated as command execution; `.exec(...)` method calls are now excluded from process execution detection.

## Residual Risk

This was static analysis only. It does not prove runtime reachability, sanitize all interprocedural flows, or validate dependency integrity beyond manifest/lockfile text. A production review should add package audit metadata, deeper AST-based taint tracking, and targeted manual review for the blocking files above.
