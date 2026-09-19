# GitHub Action — PR Security Scan Implementation Plan

> **For agentic workers:** use superpowers:subagent-driven-development or executing-plans. Checkbox tasks.

**Goal:** Ship a composite GitHub Action (`action.yml`) that lets any repo run `repo-auditor` on its code from a workflow: scan → job summary → optional PR comment → fail the check on Block. Plus a self-test workflow for this repo.

**Architecture:**

- `action.yml` (repo root, composite action):
  - Inputs: `target` (default `.`), `formats` (default `markdown,json,sarif`), `network-policy` (default `offline`), `fail-on-block` (default `true`), `pr-comment` (default `false`).
  - Outputs: `decision` (Pass/Monitor/Needs Review/Block), `report-path` (markdown report file).
  - Steps:
    1. Checkout the action's own repo (`actions/checkout@v4` with `repository: ${{ github.action_repository }}`, `ref: ${{ github.action_ref }}`, `path: _repo-auditor`) — composite actions don't auto-checkout their own code.
    2. `actions/setup-node@v4` (node 20, cache npm).
    3. `npm ci && npm run build` inside `_repo-auditor`.
    4. Run the scan: `node _repo-auditor/packages/cli/dist/index.js scan <target> --format <formats> --output repo-auditor-reports` with the network policy flag; capture exit code; append the markdown report to `$GITHUB_STEP_SUMMARY`; set outputs.
    5. Final gate step: if `fail-on-block == 'true'` and decision == Block → exit 1 (fail the job).
    6. PR comment step (`if: inputs.pr-comment == 'true'`): `actions/github-script@v7` — find an existing comment titled `<!-- repo-auditor-report -->` on the PR, update or create it with the markdown report (truncated to GitHub's 65536-char comment limit), requires `permissions: pull-requests: write` in the consuming workflow.
- `.github/workflows/scan-self-test.yml`: runs the action on `fixtures/malicious-package` expecting decision Block (job passes when the action correctly reports Block); runs on push/PR to main.
- `examples/security-scan.yml`: copy-paste consumer workflow (checkout → use this action → PR comment enabled, `permissions` documented).
- README: "GitHub Action" usage section.
- Test: `packages/cli/tests/action.test.ts` — structure assertions on `action.yml` (composite runner, inputs/outputs present, self-checkout step, scan step ordering, fail-on-block gate, pr-comment guard) + valid YAML parse + self-test workflow exists and references the action.

**Out of scope:** AI review in CI (needs data-sharing policy + secret UX), publishing to npm (action installs from the GitHub repo), SARIF upload-as-code-scanning (consumer can add `github/codeql-action/upload-sarif` themselves — documented in README).

**Context:** repo root `/Users/fred/ai/my_opencode/ai_repository_security_review`. The vitest root config only includes `packages/**/*.test.ts` and `apps/**/*.test.ts`, so the action test lives in `packages/cli/tests/` and reads `action.yml` via a relative path. CLI builds via `npm run build --workspace @repo-auditor/cli` → `packages/cli/dist/index.js`. Local smoke: run the built CLI scan on `fixtures/malicious-package` and expect exit code 2.

---

### Task 1: `action.yml` composite action
- [ ] Write `action.yml` per the Architecture spec above (composite, inputs/outputs, self-checkout, setup-node, build, scan step with exit-code capture + step summary, fail-on-block gate, optional pr-comment with comment upsert).
- [ ] Validate YAML parses: `node -e "const yaml=require('yaml');yaml.parse(require('fs').readFileSync('action.yml','utf8'))"` (yaml is a scanner-core dependency, available in node_modules).
- [ ] Local smoke: `npm run build --workspace @repo-auditor/cli && node packages/cli/dist/index.js scan fixtures/malicious-package --format markdown,json,sarif --output /tmp/ocr-action-smoke --offline; echo "exit=$?"` — expect `exit=2` and report files in /tmp/ocr-action-smoke.

### Task 2: Self-test workflow + example consumer workflow + README
- [ ] `.github/workflows/scan-self-test.yml` — on push/PR to main: checkout, use this action (`uses: ./`) with target `fixtures/malicious-package`, fail-on-block `false`; assert step outputs decision == Block via a follow-up step (job succeeds when Block is correctly reported).
- [ ] `examples/security-scan.yml` — consumer workflow with `permissions: pull-requests: write` + `contents: read`, `uses: <owner>/<repo>@main`, `pr-comment: true`.
- [ ] README section "GitHub Action" with the consumer snippet + notes (offline default, fail-on-block, SARIF upload hint).

### Task 3: Structure test (TDD)
- [ ] `packages/cli/tests/action.test.ts` — read `action.yml` (path.join(__dirname, "../../action.yml")): valid YAML; `runs.using == "composite"`; inputs contain target/formats/network-policy/fail-on-block/pr-comment; outputs contain decision/report-path; steps include actions/checkout with `github.action_repository`, setup-node, the scan run step referencing `packages/cli/dist/index.js`, a fail-on-block gate, pr-comment step guarded by `if:`; self-test workflow file exists and contains `uses: ./`.
- [ ] Run `npx vitest run packages/cli` (and full `npx vitest run packages`) green; typecheck `npm run typecheck --workspace @repo-auditor/cli` clean.

### Task 4: Verification + commit
- [ ] Full gates: `npx vitest run packages apps` equivalent from root, typecheck workspaces.
- [ ] Commits per task (`feat: add composite GitHub Action for PR security scan`, `ci: self-test the security scan action`, `test: assert action.yml structure`, docs in Task 2 commit).
