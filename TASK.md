# TASK.md

## Completed
- Added i18n keys for trust score, verdict, matrix, surface to all three language blocks (en, zh-TW, zh-CN) in `packages/scanner-core/src/i18n.ts`
- Build passes, all 59 tests pass
- Removed stale `apps/electron/dist/` directory
- Reordered provider defaults: Ollama first (works without API key)
- Added `.hint.error` / `.hint.success` CSS for visible status feedback
- Added `ai-connection:test` IPC channel, preload bridge, main handler
- Added "Test Connection" button next to Base URL
- Connection status clears when provider settings change
- **Fixed: preload script changed from ESM (.ts → .js) to CommonJS (.cjs)** — Electron renderer preload context does not reliably support ESM imports. Preload is now `src/preload.cjs` using `require("electron")`, copied to `build/preload.cjs` during build.
- Updated `main.ts` to load `build/preload.cjs`
- Updated `tsconfig.json` to exclude `preload.ts`
- Updated electron-builder `files` to include `preload.cjs`
- All 78 tests pass, all typechecks pass
- Implemented `buildRiskMatrix` and `buildAttackSurface` in `reporters.ts`
- Exported from `index.ts` with type `RiskMatrixRow`
- **Task 5: Implemented `renderHtmlReport` in `reporters.ts`** — produces self-contained HTML report with header, executive summary, trust score card, risk matrix, attack surface, findings table, data flow diagram, and footer
- All 79 tests pass, all typechecks pass
- **Task 6: Integrated HTML report output and attack surface into scan pipeline** — added `renderHtmlReport` and `buildAttackSurface` imports to `scan.ts`, computed attack surface in `scanTarget()`, added HTML format handling in `renderOutputs()`
- All 79 tests pass, all typechecks pass
- Commit: `eb3675e` feat: integrate HTML report output and attack surface into scan pipeline

- **Task 9: Added risk matrix and attack surface to Markdown report** — added `renderRiskMatrixText` helper and integrated risk matrix table + attack surface bullet list into `renderMarkdownReport`
- All 79 tests pass, all typechecks pass
- Commit: `e5889a9` feat: add risk matrix and attack surface to Markdown report

- **Rules Editor Improvement:**
  - Replaced raw JSON textarea with card-based UI showing each rule with name, severity badge, match summary
  - Added enable/disable toggle per rule (set `enabled: false`, skipped during scan)
  - Added inline JSON editing per card with validation (name, severity, match required)
  - Added Add/Delete rules with confirmation dialog
  - Added filter/search by rule name or description
  - Added Save All button that writes via ipc.rulesSave
  - Added unsaved changes guard on modal close, Escape key to collapse card or close modal
  - Commit: `0c57471` feat: improve rules editor with card-based UI, toggle, search, validation

## Pending
- (none — Phase 2 PDF export complete, ready for Phase 3 planning)
