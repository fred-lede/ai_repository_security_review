# Phase 2: PDF Export Design

**Date:** 2026-06-15  
**Status:** Approved  
**Approach:** Electron printToPDF from HTML report

---

## Goal

Add PDF export to the Repository Security Auditor. Users can check "PDF" in the sidebar, run a scan, and get a professionally formatted `report.pdf` alongside other outputs.

---

## Approach

Use Electron's `webContents.printToPDF()` on a hidden BrowserWindow loaded with the existing `renderHtmlReport()` output. This ensures the PDF is visually identical to the HTML report with zero extra rendering logic.

| Alternative | Why Not |
|---|---|
| pdfkit (Node) | Separate layout engine, Chinese/tables hard, drifts from HTML |
| Puppeteer | Extra Chromium dependency, conflicts with Electron |

---

## Architecture

### Flow

```
User checks PDF checkbox
  → scan:start runs normally
  → renderOutputs() produces outputs.pdf (= HTML string from renderHtmlReport)
  → Renderer calls report:export with outputs including .pdf
  → Main process detects outputs.pdf
  → Creates hidden BrowserWindow, loads HTML via data URL
  → webContents.printToPDF({ pageSize: "A4", printBackground: true })
  → Writes report.pdf to outputDir
  → Destroys hidden BrowserWindow
```

### Key Decisions

1. **`"pdf"` added to `OutputFormat` union** — `scanTarget()` renderOutputs maps `"pdf"` to the same HTML string as `"html"` (via `renderHtmlReport()`)
2. **PDF generation only in Electron main process** — `report:export` handler does the printToPDF conversion
3. **CLI degradation** — If `--output pdf` is used in CLI (no Electron), print a warning "PDF format requires Electron desktop app; outputting HTML instead" and write the HTML string as `report.html`
4. **No new IPC channels** — `scan:start` and `report:export` already handle everything

---

## PDF Content Structure

One PDF covers all three content levels the user selected:

| Section | Page(s) | Content |
|---|---|---|
| Summary Card | 1 | Trust Score (big number + color), Verdict badge, overall risk level |
| Risk Matrix | 2 | Severity × Category pivot table with color-coded cells |
| Attack Surface | 2 | Grouped findings with highlights per category |
| Findings Table | 3–N | Full finding details: ID, severity, category, path, explanation, fix, tags |
| Data Flow | last | Mermaid diagram as text |

No separate PDFs needed — the existing HTML report structure already covers all three levels (summary card, full analysis, finding list).

---

## CSS Changes: `@media print`

Add print-specific CSS inside `renderHtmlReport()`'s `<style>` block. Wrapped in `@media print { ... }` so screen display is unaffected.

```css
@media print {
  body {
    max-width: none;
    width: 170mm;
    margin: 0 auto;
    padding: 10mm 15mm;
  }

  section {
    break-before: page;
  }

  section:first-of-type {
    break-before: avoid;
  }

  .card,
  .attack-entry,
  table {
    break-inside: avoid;
  }

  table thead {
    display: table-header-group;
  }

  tr {
    break-inside: avoid;
  }

  /* Remove responsive media query — irrelevant for print */
}
```

Key print rules:
- Fixed width for A4 printable area (~170mm)
- `break-before: page` on each `<section>` (except the first)
- `break-inside: avoid` on cards, attack entries, tables, and rows
- `display: table-header-group` on `<thead>` so column headers repeat on every page

---

## Code Changes

### `packages/scanner-core/src/types.ts`

```ts
export type OutputFormat = "markdown" | "json" | "sarif" | "mermaid" | "html" | "pdf";
```

### `packages/scanner-core/src/scan.ts`

Add to `renderOutputs()`:

```ts
if (selectedFormats.has("pdf")) {
  outputs.pdf = renderHtmlReport(report, lang);
}
```

### `packages/scanner-core/src/reporters.ts`

Add `@media print { ... }` block inside `renderHtmlReport()`'s `<style>`.

### `apps/electron/src/main.ts`

In `report:export` handler, add PDF post-processing:

```ts
if (payload.outputs.pdf) {
  const pdfWin = new BrowserWindow({
    width: 1200,
    height: 900,
    show: false,
    webPreferences: { offscreen: true }
  });
  await pdfWin.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(payload.outputs.pdf)}`);
  const pdfBuffer = await pdfWin.webContents.printToPDF({
    pageSize: "A4",
    printBackground: true
  });
  const pdfDest = path.join(payload.outputDir, "report.pdf");
  await fs.writeFile(pdfDest, pdfBuffer);
  written.push(pdfDest);
  pdfWin.destroy();
}
```

Filenames map update:

```ts
pdf: "report.pdf"
```

### `apps/electron/src/renderer/index.html`

Add PDF checkbox in sidebar (same pattern as HTML checkbox):

```html
<label><input type="checkbox" data-format="pdf" /> PDF</label>
```

### `apps/electron/tests/ipc.test.ts`

Add `"pdf"` to the allowed output formats assertion.

### `packages/scanner-core/src/index.ts`

No export changes needed — `renderHtmlReport` is already exported.

---

## Error Handling

- **printToPDF fails** → catch error, log warning, skip PDF file, continue exporting other formats. Return `written` array without PDF. Renderer shows "PDF export failed" status.
- **Hidden BrowserWindow crash** → wrapped in try/finally, `pdfWin.destroy()` in finally block.
- **Large report** — no special handling; Electron handles arbitrary page counts natively.

---

## Testing

| Test | Location | Assertion |
|---|---|---|
| `renderOutputs` with `"pdf"` | scanner-core | `outputs.pdf` equals `outputs.html` |
| `"pdf"` in OutputFormat | scanner-core types | TypeScript type union includes `"pdf"` |
| PDF checkbox rendering | electron ipc test | Allowed formats include `"pdf"` |
| `report:export` with `.pdf` | electron (manual) | `report.pdf` written, valid PDF bytes |

Unit tests cover the data pipeline. PDF binary generation is integration-level and verified manually.

---

## Scope Exclusions

- No PDF generation in CLI (future: could add Puppeteer as optional devDependency)
- No PDF password protection or encryption
- No custom cover page template
- No page numbers or watermarks (future enhancements)
- No table of contents auto-generation
