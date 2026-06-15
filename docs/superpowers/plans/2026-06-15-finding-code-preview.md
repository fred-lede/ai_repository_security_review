# Finding Card Code Preview — Implementation Plan

**Date:** 2026-06-15  
**Spec:** `docs/superpowers/specs/2026-06-15-finding-code-preview-design.md`

---

## Task Summary

| # | Task | Files | Test |
|---|------|-------|------|
| 1 | Add `source:read` IPC allowlist + test | `ipc.ts`, `ipc.test.ts` | verify channel in array |
| 2 | Add `source:read` handler in main process | `main.ts` | typecheck |
| 3 | Add `sourceRead` bridge method in preload | `preload.cjs` | typecheck |
| 4 | Add 4 i18n keys (en/zh-TW/zh-CN) | `i18n.ts` | existing i18n tests |
| 5 | Add 4 ui i18n keys in renderer | `index.html` (ui object) | manual / existing tests |
| 6 | Modify finding card HTML + expand/collapse JS | `index.html` | manual / existing tests |

All 6 tasks must pass: `npx vitest run`, `npx tsc --noEmit` in each workspace.

---

## Task 1: Add `source:read` to IPC allowlist + update test

**File:** `apps/electron/src/ipc.ts`

Add `"source:read"` to `allowedIpcChannels` array (after `"key:delete"`).

**File:** `apps/electron/tests/ipc.test.ts`

Add `"source:read"` to the expected array in the `"exposes only intended channels"` test.

**Verify:** `npx vitest run` in `apps/electron`

---

## Task 2: Add `source:read` IPC handler in main process

**File:** `apps/electron/src/main.ts`

Add a new `ipcMain.handle("source:read", ...)` block. Insert after the `key:delete` handler (before the `assertAllowed` function).

```ts
interface SourceReadPayload {
  basePath: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  contextLines?: number;
}

ipcMain.handle("source:read", async (_event, payload: SourceReadPayload) => {
  assertAllowed("source:read");
  const resolvedPath = path.join(payload.basePath, payload.filePath);
  const ctx = payload.contextLines ?? 5;
  try {
    const content = await fs.readFile(resolvedPath, "utf8");
    const allLines = content.split("\n");
    const start = Math.max(1, payload.lineStart - ctx);
    const end = Math.min(allLines.length, payload.lineEnd + ctx);
    const lines = allLines.slice(start - 1, end).map((line, i) => ({
      num: start + i,
      text: line
    }));
    return {
      lines,
      highlightedStart: payload.lineStart,
      highlightedEnd: payload.lineEnd
    };
  } catch {
    return { error: "File not found" };
  }
});
```

Key details:
- `path.join(basePath, filePath)` to resolve the absolute path
- `contextLines` defaults to 5 (5 lines before, 5 after)
- Returns `{ lines: [{num, text}], highlightedStart, highlightedEnd }`
- On any read error → `{ error: "File not found" }`
- Only returns requested window, never the entire file

**Verify:** `npx tsc --noEmit` in `apps/electron`

---

## Task 3: Add `sourceRead` bridge method in preload

**File:** `apps/electron/src/preload.cjs`

Add `sourceRead: (payload) => invoke("source:read", payload)` to the `contextBridge.exposeInMainWorld` object (after `keyDelete`).

**Verify:** `npx tsc --noEmit` in `apps/electron`

---

## Task 4: Add 4 i18n keys to scanner-core

**File:** `packages/scanner-core/src/i18n.ts`

Add these 4 keys to the `reportStrings` object in all 3 locales (en, zh-TW, zh-CN):

| Key | en | zh-TW | zh-CN |
|-----|----|-------|-------|
| `finding.codeSnippet` | Code Snippet | 程式碼片段 | 代码片段 |
| `finding.recommendedFix` | Recommended Fix | 建議修復 | 建议修复 |
| `finding.patchDraft` | Patch Draft | 修補草稿 | 修补草稿 |
| `finding.showContext` | Show Context | 顯示上下文 | 显示上下文 |

Note: These are distinct from `report.codeSnippet` / `report.recommendedFix` — the `finding.*` keys are shorter labels used in card context.

**Verify:** `npx vitest run` in `packages/scanner-core`

---

## Task 5: Add 4 ui i18n keys in Electron renderer

**File:** `apps/electron/src/renderer/index.html`

Add these 4 keys to each locale in the `ui` object:

| Key | en | zh-TW | zh-CN |
|-----|----|-------|-------|
| `codeSnippet` | Code Snippet | 程式碼片段 | 代码片段 |
| `recommendedFix` | Recommended Fix | 建議修復 | 建议修复 |
| `patchDraft` | Patch Draft | 修補草稿 | 修补草稿 |
| `showContext` | Show Context | 顯示上下文 | 显示上下文 |

Also add these error-state keys:

| Key | en | zh-TW | zh-CN |
|-----|----|-------|-------|
| `sourceNotAvailable` | Source file not available | 原始檔案無法使用 | 源文件无法使用 |

**Verify:** existing ipc.test.ts source scan

---

## Task 6: Modify finding card rendering (HTML + CSS + JS)

**File:** `apps/electron/src/renderer/index.html`

### 6a. CSS additions (inside `<style>` block, after `.finding` rules)

```css
.finding.expanded .finding-detail { display: block; }
.finding-detail { display: none; border-top: 1px solid #d0d7de; padding: 12px 0 4px; }
.finding-header { cursor: pointer; }
.finding-header .collapse-icon { float: right; transition: transform 0.15s; }
.finding.expanded .finding-header .collapse-icon { transform: rotate(90deg); }
.finding-code, .finding-patch, .finding-context {
  background: #f8f9fa;
  border: 1px solid #d0d7de;
  border-radius: 6px;
  padding: 8px 12px;
  margin: 6px 0;
  overflow-x: auto;
  font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, monospace;
  font-size: 13px;
  line-height: 1.5;
  white-space: pre;
}
.line-num { color: #6c757d; display: inline-block; min-width: 3ch; text-align: right; margin-right: 1em; user-select: none; }
.line-highlight { background: #fff3cd; }
.finding-fix { margin: 4px 0; }
```

### 6b. Rewrite `renderResult` finding loop (lines 1028-1036)

Replace the current finding card creation with:

```js
$("findings").replaceChildren(
  ...report.findings.map((finding) => {
    const el = document.createElement("div");
    el.className = "panel finding";
    el.dataset.risk = finding.riskLevel;

    const header = document.createElement("div");
    header.className = "finding-header";
    header.innerHTML = `<span class="collapse-icon">▶</span><strong>${localizedRisk(finding.riskLevel)}</strong> ${localizedCategory(finding.category)}<br /><span class="muted">${finding.filePath}:${finding.lineStart}${finding.lineEnd !== finding.lineStart ? '-' + finding.lineEnd : ''}</span>`;

    const detail = document.createElement("div");
    detail.className = "finding-detail";

    // Explanation
    const explanationP = document.createElement("p");
    explanationP.textContent = localizedExplanation(finding.explanation);
    detail.appendChild(explanationP);

    // Code Snippet
    if (finding.codeSnippet) {
      const h4 = document.createElement("h4");
      h4.textContent = t("codeSnippet");
      detail.appendChild(h4);
      const pre = document.createElement("pre");
      pre.className = "finding-code";
      const code = document.createElement("code");
      const lines = finding.codeSnippet.split("\n");
      code.textContent = finding.lineStart
        ? lines.map((line, i) => `${String(finding.lineStart + i).padStart(4)} │ ${line}`).join("\n")
        : finding.codeSnippet;
      pre.appendChild(code);
      detail.appendChild(pre);
    }

    // Recommended Fix
    if (finding.recommendedFix) {
      const h4 = document.createElement("h4");
      h4.textContent = t("recommendedFix");
      detail.appendChild(h4);
      const p = document.createElement("p");
      p.className = "finding-fix";
      p.textContent = finding.recommendedFix;
      detail.appendChild(p);
    }

    // Patch Draft
    if (finding.remediation?.patchDraft) {
      const h4 = document.createElement("h4");
      h4.textContent = t("patchDraft");
      detail.appendChild(h4);
      const pre = document.createElement("pre");
      pre.className = "finding-patch";
      pre.textContent = finding.remediation.patchDraft;
      detail.appendChild(pre);
    }

    // Show Context button
    const ctxBtn = document.createElement("button");
    ctxBtn.className = "secondary";
    ctxBtn.textContent = t("showContext");
    ctxBtn.addEventListener("click", async (e) => {
      e.stopPropagation();
      if (!state.result?.report?.target?.localPath) {
        ctxBtn.replaceWith(Object.assign(document.createElement("span"), { textContent: t("sourceNotAvailable"), className: "muted" }));
        return;
      }
      ctxBtn.disabled = true;
      ctxBtn.textContent = "...";
      try {
        const result = await window.repoAuditor.sourceRead({
          basePath: state.result.report.target.localPath,
          filePath: finding.filePath,
          lineStart: finding.lineStart,
          lineEnd: finding.lineEnd,
          contextLines: 5
        });
        if (result.error) {
          ctxBtn.replaceWith(Object.assign(document.createElement("span"), { textContent: t("sourceNotAvailable"), className: "muted" }));
          return;
        }
        const pre = document.createElement("pre");
        pre.className = "finding-context";
        pre.textContent = result.lines.map((l) => {
          const prefix = String(l.num).padStart(4) + " │ ";
          const isHighlight = l.num >= result.highlightedStart && l.num <= result.highlightedEnd;
          return isHighlight ? `>>> ${prefix}${l.text}` : `    ${prefix}${l.text}`;
        }).join("\n");
        ctxBtn.replaceWith(pre);
      } catch {
        ctxBtn.replaceWith(Object.assign(document.createElement("span"), { textContent: t("sourceNotAvailable"), className: "muted" }));
      }
    });
    detail.appendChild(ctxBtn);

    el.appendChild(header);
    el.appendChild(detail);

    // Expand/collapse
    header.addEventListener("click", () => {
      const wasExpanded = el.classList.contains("expanded");
      // Collapse all
      document.querySelectorAll(".finding.expanded").forEach((f) => f.classList.remove("expanded"));
      if (!wasExpanded) el.classList.add("expanded");
    });

    return el;
  })
);
```

**Verify:** `npx vitest run` in all workspaces, `npx tsc --noEmit` in all workspaces

---

## Execution Order

Tasks 1→2→3 are sequential (IPC allowlist first, then handler, then bridge).
Tasks 4 and 5 are independent of 1-3 (i18n only).
Task 6 depends on both 1-3 and 5 (uses the bridge and the ui keys).

Recommended order: **1 → 2 → 3 → 4 → 5 → 6**
