# AI Review Session Persistence & Resume — Phase C Implementation Plan

> **For agentic workers:** use superpowers:subagent-driven-development or executing-plans. Checkbox tasks.

**Goal:** Persist AI review batch progress to disk and let an interrupted review resume: `runAiReview` gets `sessionDir`/`resumeSessionId` options; Electron gains `session:list` + resume-capable `ai-review:run` IPC and a small "Sessions" UI in the sidebar.

**Storage locations (agreed):** Electron → `<userData>/sessions/`; CLI/other callers → caller passes `scanPath/.repo-auditor/sessions` explicitly (cli wiring NOT in this phase).

**Architecture:**

- `packages/ai-review/src/session.ts` (new, pure-ish Node module):
  - `AiReviewSession = { id, fingerprint, createdAt, updatedAt, status: "running"|"done"|"interrupted", scanPath, findingIds: string[], batches: Array<{ index: number; summary: string; notes: AgentNote[]; newFindings: AiNewFinding[] }> }`
  - `sessionFingerprint(provider: AiProviderConfig, findings: Finding[]): string` — sha256 hex (first 16) over `{type,baseUrl,model,language,dataSharingMode,redactionEnabled}` + sorted finding ids.
  - `sessionId(fingerprint) => `${Date.now()}-${fingerprint}`` for new sessions.
  - `loadSession(dir, id?): Promise<AiReviewSession | undefined>` — latest matching, or by id.
  - `findResumableSession(dir, fingerprint): Promise<AiReviewSession | undefined>` — newest file whose fingerprint matches and status !== "done".
  - `saveSession(dir, session): Promise<void>` — atomic write (`writeFile(tmp)` + `rename(tmp→id.json)` + mkdir recursive).
  - `listSessions(dir): Promise<Array<{ id, createdAt, updatedAt, status, scanPath, findingCount, batchesDone }>>` — sorted newest first. (read file, tolerate corrupt JSON by skipping)
- `runAiReview` extension (`review.ts`):
  - `AiReviewOptions` += `sessionDir?: string; resumeSessionId?: string;`
  - Start: if `sessionDir`, compute fingerprint; `findResumableSession` (or by explicit id). Seed `summaries/notes/rawNewFindings` from `session.batches` and skip those batch indexes in the loop.
  - After each completed batch: upsert into in-memory session object and `await saveSession` (best-effort, swallow errors — session loss must never fail a review).
  - End: set status `"done"` and save; on abort/error break, status stays `"running"` (= resumable later).
  - `AiReviewResult` += `sessionId?: string; resumedFromSession?: string;`
- Electron:
  - `main.ts`: `SESSIONS_DIR = path.join(app.getPath("userData"), "sessions")`; IPC `session:list` → `listSessions(SESSIONS_DIR)`; `ai-review:run` payload += `resumeSessionId?` → passes `{ sessionDir: SESSIONS_DIR, resumeSessionId }` into `runAiReview`; reply may include `sessionId`/`resumedFromSession`.
  - `preload.cjs`: expose `sessionList()` → `session:list`.
  - `renderer/index.html`: sidebar section under export-status: "Sessions" — populated from `sessionList()` after every review/scan; each interrupted row gets a 續跑/Resume button calling `aiReviewRun({ resumeSessionId: id, ... })` with the same provider config; i18n keys in 3 locales; status line shows resume state.
- All-or-nothing test gates: ai-review unit tests (session store round-trip, fingerprint stability/mismatch, resume skips completed batches via fetch-call counts, best-effort save failure tolerated), electron source-inspection tests (preload exports, main.ts handler registrations, renderer strings).

**Out of scope:** deep-dive resume (single-shot by design), CLI flags, session UI polish (tree etc.).

**Context:** run from repo root. Tests: `npx vitest run packages/ai-review` / `npx vitest run apps/electron`; typecheck `npm run typecheck --workspace @repo-auditor/<name>`; the electron ipc tests are source-inspection regex tests.

---

### Task 1: `session.ts` store + types + tests (TDD)
- Create `packages/ai-review/src/session.ts` per spec above; add `sessionDir?/resumeSessionId?` to `AiReviewOptions`, `sessionId?/resumedFromSession?` to `AiReviewResult`; export everything from `index.ts`; tests `packages/ai-review/tests/session.test.ts` covering: fingerprint stable + differs on model change; save→load round-trip; findResumableSession picks newest matching, skips "done"; saveSession works when dir missing (creates); listSessions sorted, skips corrupt files; saving to an unwritable dir does not throw (swallow).

### Task 2: Resume logic in `runAiReview` (TDD)
- Wire session into the batch loop (seed + skip + persist + status transitions). Tests in `review.test.ts`: (a) `sessionDir` set → session file written with status "done" after complete run; (b) resume: preload a session with batch 0 done (finding-1), rerun → fetchImpl called only for remaining batches, `resumedFromSession` set, summaries include seeded one; (c) fingerprint mismatch → fresh run, no skip; (d) save failure tolerated (sessionDir pointing to invalid location) → review still completes, `sessionId` undefined.

### Task 3: Electron IPC + preload
- `main.ts`: sessions dir, `session:list` handler, `resumeSessionId` passthrough in `ai-review:run`. `preload.cjs`: `sessionList`. Add allowlist entries in `assertAllowed` for `session:list` if applicable. Tests in `apps/electron/tests/ipc.test.ts` (source-inspection style — assert handler/preload strings).

### Task 4: Renderer Sessions UI (TDD = source-inspection tests in ipc.test.ts)
- Sidebar section under `#export-status`: `<div id="sessions">` + heading i18n `sessionsTitle` (en/"Sessions", zh-TW/"工作階段", zh-CN/"会话"), per-session row with resume button (`data-i18n="resume"`), refresh after each AI review; only render rows when list non-empty; resume click uses same provider config and shows progress via existing `ai-review:progress`.
- Keep the section minimal (existing sidebar is plain); do not add CSS framework changes.

### Task 5: Verification
- `npx vitest run packages/ai-review` green; `npx vitest run apps/electron` green; `npm run typecheck --workspaces --if-present` clean; `npm run build --workspace @repo-auditor/ai-review`. Commit each task separately.
