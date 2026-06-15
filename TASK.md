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

## Pending
- (none)
