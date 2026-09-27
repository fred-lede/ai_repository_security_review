# Progress Log

## 2026-09-27: Electron UI Design & Layout Improvements

Reworked `apps/electron/src/renderer/index.html` (single-file UI) for clearer hierarchy,
responsiveness, and accessibility:

- **Sticky CTA footer**: wrapped settings in `.settings-scroll` (scrollable) and moved
  Run / AI Review / Export into a fixed `.actions-footer`; AI Review + Export share a
  50/50 `.pair` row, Edit Rules demoted to a text link. Primary action always visible.
- **Responsive sidebar**: `main` grid now `clamp(280px, 26vw, 360px)` so the sidebar
  narrows instead of the 980px breakpoint snapping the whole layout to one column.
- **Unified risk palette**: extracted `--risk-*` CSS vars; finding left-border,
  `severityBadge()`, and HTML-report colors all align now (High no longer amber in
  one place / orange in another).
- **Finding severity filter + sort**: new toolbar (All / Critical+ / High+ / Medium+ /
  Low+), findings always sorted Critical-first; filter re-renders live.
- **Preview tabs**: Markdown / JSON / SARIF / Mermaid tabs above the report preview
  instead of raw single-source text.
- **Skeleton loading**: `#findings` + `#preview` show shimmer bars during a scan,
  distinguishing "scanning" from "no scan run".
- **Auto-fit metrics**: `.status` uses `repeat(auto-fit, minmax(120px,1fr))`.
- **Accessibility**: finding headers now `role=button` + `tabindex` + keyboard
  toggle + `aria-expanded`; `:focus-visible` outlines; small buttons given min-height.
- **Dark mode**: full `prefers-color-scheme: dark` theme on top of the new CSS vars.
- **i18n**: added `filterAll/Critical/High/Medium/Info` + `tabMarkdown/Json/Sarif/
  Mermaid` keys in EN/zh-TW/zh-CN and wired to the filter `<select>` + tab labels.
- **Rules modal**: capped inner list to `min(50vh,400px)` to stop double-scroll.

Tests: updated `apps/electron/tests/ipc.test.ts` assertion to the refactored preview
code (`result.outputs?.[format]`); full suite 257 pass, the single remaining failure
is the pre-existing Windows-specific `session.test.ts` unwritable-path test (unrelated).

## 2026-09-27: Phase 3 — Cloudflare Multi-Phase Security Audit Complete

Adopted the Cloudflare `security-audit-skill` methodology (https://github.com/cloudflare/security-audit-skill):
a structured six-phase audit with independently verified, machine-readable findings, layered on top of the
existing deterministic scanner.

New modules in `packages/scanner-core/src/`:
- `reconnaissance.ts` (Phase 1) — maps application type, tech stack, trust boundaries, input surfaces,
  comparable baseline; initializes a `coverage-ledger.json` of attack-class/subsystem/entry-point units.
- `hunting.ts` (Phase 2) — coverage-led hunting: per-attack-class hunters (`injection`, `access-control`,
  `resource-file-handling`, `cryptography-secrets`, `electron-ipc`, `supply-chain`) with a hunting
  methodology, disproof rules, and a coverage critic that flags gaps.
- `validation.ts` (Phase 3) — every unique candidate gets a fresh verifier that tries to disprove it;
  three verdicts: `confirmed` / `needs_validation` / `rejected`.
- `structuredOutput.ts` (Phase 4) — machine-readable `findings.json` with a deterministic schema
  validator, plus `mergePriorFindings()` for additive runs (skip known findings, carry forward evidence).
- `independentVerification.ts` (Phase 5) — fresh pass re-checks final source claims against on-disk file
  content; material failures demote `confirmed`→`needs_validation` and receive a second verifier.
- `targetNeutralReporting.ts` (Phase 6) — derives `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`
  from verified records + coverage ledger.
- `audit.ts` — orchestrates all six phases; `validateCoverageLedger()` runs after the ledger is created
  and after each update.

Integration:
- `runFullAudit()` is exported from `index.ts`; `attachAuditToReport()` projects audit findings onto the
  classic `AuditReport` so markdown/json/sarif/html/pdf pipelines keep working.
- New CLI command `repo-auditor audit <target>` writes REPORT.md, FINDINGS-DETAIL.md, NEEDS-VALIDATION.md,
  findings.json, coverage-ledger.json; `--prior <path>` supports additive runs; exits non-zero on
  confirmed findings (CI gate ready).

Verification:
- 11 new tests in `packages/scanner-core/tests/audit.test.ts` all pass (reconnaissance, hunting+validation,
  structured output, independent verification, target-neutral reporting, end-to-end orchestration).
- Full workspace typecheck passes (scanner-core, ai-review, cli, electron).
- Pre-existing unrelated failure: `packages/ai-review/tests/session.test.ts` (`/dev/null/impossible`
  unwritable-path test) fails on Windows; untouched by this work.

## 2026-06-15: Phase 1 Report Enhancement Complete

- **Task 1:** Added `html` OutputFormat, `AttackSurfaceEntry` interface, `attackSurface` field to AuditReport
- **Task 2:** Added 17 i18n keys (trust score, verdict, matrix, surface) across EN/zh-TW/zh-CN
- **Task 3:** Created `trustScore.ts` with `computeTrustScore()` and `computeFinalVerdict()` functions
- **Task 4:** Added `buildRiskMatrix()` and `buildAttackSurface()` to reporters.ts
- **Task 5:** Implemented `renderHtmlReport()` — self-contained HTML report with Trust Score, Risk Matrix, Attack Surface, Findings Table, Data Flow
- **Task 6:** Integrated HTML output and attack surface computation into scan pipeline
- **Task 7:** Fixed all test fixtures missing `attackSurface` field (reporters, ai-review, types tests)
- **Task 8:** Added HTML checkbox to Electron UI sidebar + App.tsx outputFormats + ipc tests
- **Task 9:** Added `renderRiskMatrixText()` helper and integrated Risk Matrix + Attack Surface into Markdown reports

All 79 tests pass, all typechecks pass.

## 2026-06-15: Rules Editor Improvement Complete

- Replaced raw JSON textarea with card-based UI (name, severity badge, match summary per card)
- Added enable/disable toggle per rule (sets `enabled: false`, skipped during scan)
- Added inline JSON editing per card with validation (name, severity, match required)
- Added Add/Delete rules with confirmation dialog
- Added filter/search by rule name or description
- Added Save All button via ipc.rulesSave
- Added unsaved changes guard on modal close; Escape key to collapse card or close modal
- Commit: `0c57471`

All 79 tests pass, all typechecks pass.

## 2026-06-15: Phase 2 PDF Export Complete

- Added `"pdf"` to `OutputFormat` union
- Added `"pdf"` case in `renderOutputs()` (same HTML content as `"html"`)
- Added `@media print` CSS to `renderHtmlReport()` for A4 page layout
- Added CLI degradation: `--format pdf` prints warning and outputs HTML instead
- Added PDF checkbox in Electron sidebar
- Added `printToPDF` handler in `report:export`: hidden BrowserWindow → load HTML → `webContents.printToPDF()` → write `report.pdf`
- Commits: `704ad02`, `d8a63b8`, `0076d89`, `4e72ae0`, `730af51`, `6bb3155`

All 81 tests pass, all typechecks pass.
