# Handoff: Phase 1 + Rules Editor + Phase 2 PDF Export Complete

## State

- All 9 tasks of Phase 1 implemented and verified
- Rules editor improvement (card-based UI, toggle, search, validation) done
- Phase 2 PDF export (6 tasks) done
- 81 tests passing, clean typecheck across all workspaces
- Last commit: `6bb3155` (printToPDF export handler)
- Branch: `main`

## What Was Built (Phase 1)

- Trust Score (0-100) with color-coded labels and final verdict
- Risk Matrix (severity × category pivot table)
- Attack Surface Summary (grouped by category with highlights)
- Self-contained HTML report renderer (inline CSS, no JS required)
- i18n for all new UI elements (EN/zh-TW/zh-CN)
- Markdown report now includes Risk Matrix and Attack Surface sections
- Electron UI has HTML output format checkbox

## What Was Built (Rules Editor)

- Card-based rule list with name, severity badge, match summary
- Enable/disable toggle per rule
- Inline JSON editing with validation
- Add/delete rules with confirmation dialog
- Filter/search by name or description
- Save All button with unsaved changes guard

## What Was Built (Phase 2 PDF Export)

- `"pdf"` added to `OutputFormat` union
- `renderOutputs()` maps `"pdf"` to same HTML as `"html"`
- `@media print` CSS for A4 page layout in `renderHtmlReport()`
- CLI degradation: `--format pdf` warns + outputs HTML instead
- Electron sidebar PDF checkbox
- `report:export` handler creates hidden BrowserWindow, loads HTML, calls `printToPDF()`, writes `report.pdf`
- Error handling: try/catch/finally around hidden BrowserWindow

## Key Files Added

- `packages/scanner-core/src/trustScore.ts` — `computeTrustScore()`, `computeFinalVerdict()`

## Key Files Modified

- `packages/scanner-core/src/types.ts` — OutputFormat includes `"pdf"`, AttackSurfaceEntry, AuditReport.attackSurface
- `packages/scanner-core/src/i18n.ts` — 17 new i18n keys
- `packages/scanner-core/src/reporters.ts` — `buildRiskMatrix()`, `buildAttackSurface()`, `renderHtmlReport()`, `renderRiskMatrixText()`, `@media print` CSS
- `packages/scanner-core/src/scan.ts` — attackSurface computation, html/pdf output in renderOutputs
- `packages/scanner-core/src/index.ts` — exports for new functions
- `packages/cli/src/index.ts` — `pdf` in outputFiles, allowed formats, degradation warning
- `apps/electron/src/main.ts` — safeStorage handlers, external rules, printToPDF in report:export
- `apps/electron/src/renderer/App.tsx` — outputFormats includes `"html"`, `"pdf"`
- `apps/electron/src/renderer/index.html` — HTML checkbox, PDF checkbox, card-based rules editor
- `apps/electron/tests/ipc.test.ts` — output format assertion includes `"pdf"`

## Implementation Notes

- `renderHtmlReport` computes trust score and risk matrix internally — caller just passes `(report, lang)`
- `buildAttackSurface` accepts `AuditReport` and uses `report.findings` (not `ProjectInventory`)
- `buildRiskMatrix` returns `RiskMatrixRow[]` (not `Record<string, Record<string, number>>`)
- `renderHtmlReport` calls `buildAttackSurface` and `buildRiskMatrix` internally; the values stored on `report.attackSurface` are consumed by the scan pipeline export but reporters recompute
- Rules editor is entirely in `index.html` — no IPC or React changes needed beyond existing `rules:load`/`rules:save` channels
- Preload bridge (.cjs) is required — Electron renderer preload does not support ESM
- PDF generation: hidden BrowserWindow with `offscreen: true`, loads data URL, `printToPDF({ pageSize: "A4", printBackground: true })`
- CLI `--format pdf` degrades to HTML output with warning; real PDF requires Electron

## Phase 3 Candidates (Ready for Decision)

1. **Report Diff** — compare two scans, highlight changed findings
2. **Multi-Project Dashboard** — overview page comparing scan results across repos
3. **CI/CD Integration** — GitHub Actions security gate, fail on Block verdict
4. **Vulnerability DB Lookup** — CVE cross-reference for detected packages
