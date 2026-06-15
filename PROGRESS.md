# Progress Log

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
