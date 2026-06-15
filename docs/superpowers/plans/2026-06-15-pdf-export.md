# PDF Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add PDF export to the Repository Security Auditor via Electron's printToPDF, using the existing HTML report as source.

**Architecture:** `"pdf"` added to `OutputFormat` union. `renderOutputs()` maps `"pdf"` to the same HTML string as `"html"`. Electron main process creates a hidden BrowserWindow, loads the HTML, calls `webContents.printToPDF()`, and writes the buffer to disk. CLI degrades gracefully by writing HTML instead.

**Tech Stack:** TypeScript, ESM, Vitest, Electron `webContents.printToPDF()`, `@media print` CSS

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `packages/scanner-core/src/types.ts` | Modify | Add `"pdf"` to `OutputFormat` union |
| `packages/scanner-core/src/scan.ts` | Modify | Add `"pdf"` case in `renderOutputs()` |
| `packages/scanner-core/src/reporters.ts` | Modify | Add `@media print` CSS in `renderHtmlReport()` |
| `packages/scanner-core/tests/types.test.ts` | Modify | Assert `"pdf"` in OutputFormat |
| `packages/scanner-core/tests/scan.test.ts` | Modify | Test `"pdf"` in renderOutputs |
| `packages/cli/src/index.ts` | Modify | Add `pdf` → `report.pdf` mapping, CLI degradation warning |
| `packages/cli/tests/cli.test.ts` | Modify | Test `--format pdf` degraded to HTML warning |
| `apps/electron/src/renderer/App.tsx` | Modify | Add `"pdf"` to `outputFormats` array |
| `apps/electron/src/renderer/index.html` | Modify | Add PDF checkbox in sidebar |
| `apps/electron/src/main.ts` | Modify | Add printToPDF handler in `report:export` |
| `apps/electron/tests/ipc.test.ts` | Modify | Assert `"pdf"` in output formats |

---

### Task 1: Add `"pdf"` to OutputFormat and types test

**Files:**
- Modify: `packages/scanner-core/src/types.ts:15`
- Modify: `packages/scanner-core/tests/types.test.ts`

- [ ] **Step 1: Update OutputFormat union**

In `packages/scanner-core/src/types.ts`, change line 15 from:

```ts
export type OutputFormat = "markdown" | "json" | "sarif" | "mermaid" | "html";
```

to:

```ts
export type OutputFormat = "markdown" | "json" | "sarif" | "mermaid" | "html" | "pdf";
```

- [ ] **Step 2: Add types test for `"pdf"`**

In `packages/scanner-core/tests/types.test.ts`, add a test asserting `"pdf"` is a valid `OutputFormat`:

```ts
it("includes pdf as a valid OutputFormat", () => {
  const formats: OutputFormat[] = ["markdown", "json", "sarif", "mermaid", "html", "pdf"];
  expect(formats).toContain("pdf");
});
```

- [ ] **Step 3: Run scanner-core tests**

Run: `npx vitest run packages/scanner-core/tests/types.test.ts`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add packages/scanner-core/src/types.ts packages/scanner-core/tests/types.test.ts
git commit -m "feat: add pdf to OutputFormat union"
```

---

### Task 2: Add `"pdf"` case to renderOutputs and scan test

**Files:**
- Modify: `packages/scanner-core/src/scan.ts:77-79`
- Modify: `packages/scanner-core/tests/scan.test.ts`

- [ ] **Step 1: Add `"pdf"` case in renderOutputs()**

In `packages/scanner-core/src/scan.ts`, after the `html` block (line 77-79), add:

```ts
  if (selectedFormats.has("pdf")) {
    outputs.pdf = renderHtmlReport(report, lang);
  }
```

The full `renderOutputs` function should now be:

```ts
function renderOutputs(report: AuditReport, outputFormats: OutputFormat[], lang: Language = "zh-TW"): ScanResult["outputs"] {
  const selectedFormats = new Set(outputFormats);
  const outputs: ScanResult["outputs"] = {
    decision: renderDecisionRecord(report, lang),
    remediation: renderRemediationList(report, lang)
  };

  if (selectedFormats.has("markdown")) {
    outputs.markdown = renderMarkdownReport(report, lang);
  }

  if (selectedFormats.has("json")) {
    outputs.json = renderJsonReport(report, lang);
  }

  if (selectedFormats.has("mermaid")) {
    outputs.mermaid = renderMermaidDataFlow(report.dataFlow);
  }

  if (selectedFormats.has("sarif")) {
    outputs.sarif = renderSarifReport(report, lang);
  }

  if (selectedFormats.has("html")) {
    outputs.html = renderHtmlReport(report, lang);
  }

  if (selectedFormats.has("pdf")) {
    outputs.pdf = renderHtmlReport(report, lang);
  }

  return outputs;
}
```

- [ ] **Step 2: Add scan test for pdf output**

In `packages/scanner-core/tests/scan.test.ts`, add a test inside the `describe("scan orchestration")` block:

```ts
  it("renders pdf output as the same HTML content as html output", async () => {
    const result = await scanTarget(path.resolve("fixtures/malicious-package"), {
      reviewMode: "full-audit",
      networkPolicy: "offline",
      outputFormats: ["html", "pdf"]
    });

    expect(result.outputs.pdf).toBe(result.outputs.html);
    expect(result.outputs.pdf).toContain("<!DOCTYPE html>");
    expect(result.outputs.pdf).toContain("Trust Score");
  });
```

Note: Add `path` import at the top if not already present (it is — line 1).

- [ ] **Step 3: Run scanner-core tests**

Run: `npx vitest run packages/scanner-core/tests/scan.test.ts`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add packages/scanner-core/src/scan.ts packages/scanner-core/tests/scan.test.ts
git commit -m "feat: add pdf output to scan pipeline (same content as html)"
```

---

### Task 3: Add `@media print` CSS to renderHtmlReport

**Files:**
- Modify: `packages/scanner-core/src/reporters.ts:431`

- [ ] **Step 1: Add print CSS before the closing `</style>` tag**

In `packages/scanner-core/src/reporters.ts`, replace the line:

```ts
@media(max-width:768px){body{padding:1rem}table{font-size:0.75rem}th,td{padding:0.25rem 0.5rem}}
```

with:

```ts
@media(max-width:768px){body{padding:1rem}table{font-size:0.75rem}th,td{padding:0.25rem 0.5rem}}@media print{body{max-width:none;width:170mm;margin:0 auto;padding:10mm 15mm}section{break-before:page}section:first-of-type{break-before:avoid}.card,.attack-entry,table{break-inside:avoid}table thead{display:table-header-group}tr{break-inside:avoid}}
```

This adds `@media print` rules for:
- Fixed width (170mm A4 printable area)
- `break-before: page` on each `<section>` (except first)
- `break-inside: avoid` on cards, attack entries, tables, rows
- `display: table-header-group` on `<thead>` for repeating headers

- [ ] **Step 2: Run scanner-core tests**

Run: `npx vitest run packages/scanner-core/tests`
Expected: All tests pass

- [ ] **Step 3: Commit**

```bash
git add packages/scanner-core/src/reporters.ts
git commit -m "feat: add @media print CSS to HTML report for PDF export"
```

---

### Task 4: Add CLI degradation for `--format pdf`

**Files:**
- Modify: `packages/cli/src/index.ts:8-16`
- Modify: `packages/cli/src/index.ts:80-89`
- Modify: `packages/cli/tests/cli.test.ts`

- [ ] **Step 1: Add pdf to outputFiles mapping**

In `packages/cli/src/index.ts`, add `pdf` to the `outputFiles` record on line 8:

```ts
const outputFiles: Record<OutputFormat | "decision" | "remediation", string> = {
  html: "report.html",
  pdf: "report.pdf",
  markdown: "report.md",
  json: "findings.json",
  mermaid: "data-flow.mmd",
  sarif: "results.sarif",
  decision: "decision-record.json",
  remediation: "remediation-list.json"
};
```

- [ ] **Step 2: Add `"pdf"` to CLI allowed formats and degradation logic**

In `packages/cli/src/index.ts`, replace the `parseOutputFormats` function with:

```ts
function parseOutputFormats(value: string): OutputFormat[] {
  const formats = value.split(",").map((format) => format.trim()).filter(Boolean);
  const allowed = new Set<OutputFormat>(["markdown", "json", "mermaid", "sarif", "html", "pdf"]);
  const invalid = formats.filter((format) => !allowed.has(format as OutputFormat));

  if (invalid.length > 0) {
    throw new Error(`Unsupported output format: ${invalid.join(", ")}`);
  }

  return formats as OutputFormat[];
}
```

Then in the `scan` action handler (inside `.action(async ...)`), add after `const result = await scanTarget(...)` and before `await fs.mkdir(...)`:

```ts
      if (result.outputs.pdf && outputFormats.includes("pdf")) {
        io.writeOut("Warning: PDF format requires Electron desktop app; outputting HTML as report.html instead.\n");
        result.outputs.html = result.outputs.pdf;
        delete result.outputs.pdf;
      }
```

Note: Since `result.outputs` is `Partial<Record<ScanOutputName, string>>`, we can directly mutate the `pdf` key to move the content to `html`.

- [ ] **Step 3: Add CLI test for pdf degradation**

In `packages/cli/tests/cli.test.ts`, add a test:

```ts
  it("degrades --format pdf to HTML with a warning", async () => {
    const outputDir = await fs.mkdtemp(path.join(os.tmpdir(), "repo-auditor-cli-pdf-"));
    const output: string[] = [];
    const exitCodes: number[] = [];
    const program = createProgram({
      writeOut: (value) => output.push(value),
      setExitCode: (code) => exitCodes.push(code)
    });
    program.exitOverride();

    await program.parseAsync(
      [
        "node",
        "repo-auditor",
        "scan",
        path.resolve("fixtures/malicious-package"),
        "--offline",
        "--format",
        "pdf",
        "--output",
        outputDir
      ],
      { from: "node" }
    );

    expect(output.join("")).toContain("PDF format requires Electron");
    await expect(fs.stat(path.join(outputDir, "report.html"))).resolves.toBeDefined();
  });
```

- [ ] **Step 4: Run CLI tests**

Run: `npx vitest run packages/cli/tests/cli.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/index.ts packages/cli/tests/cli.test.ts
git commit -m "feat: add pdf to CLI format options with Electron degradation warning"
```

---

### Task 5: Add PDF checkbox to Electron UI sidebar

**Files:**
- Modify: `apps/electron/src/renderer/App.tsx:3`
- Modify: `apps/electron/src/renderer/index.html:407`
- Modify: `apps/electron/tests/ipc.test.ts:35`

- [ ] **Step 1: Add `"pdf"` to outputFormats in App.tsx**

In `apps/electron/src/renderer/App.tsx`, change line 3 from:

```ts
export const outputFormats = ["markdown", "json", "mermaid", "sarif", "html"] as const;
```

to:

```ts
export const outputFormats = ["markdown", "json", "mermaid", "sarif", "html", "pdf"] as const;
```

- [ ] **Step 2: Add PDF checkbox in index.html**

In `apps/electron/src/renderer/index.html`, after line 407 (`<label class="check"><input type="checkbox" name="format" value="html" checked /> HTML</label>`), add:

```html
            <label class="check"><input type="checkbox" name="format" value="pdf" checked /> PDF</label>
```

- [ ] **Step 3: Update ipc test assertion**

In `apps/electron/tests/ipc.test.ts`, change line 35 from:

```ts
    expect(outputFormats).toEqual(["markdown", "json", "mermaid", "sarif", "html"]);
```

to:

```ts
    expect(outputFormats).toEqual(["markdown", "json", "mermaid", "sarif", "html", "pdf"]);
```

- [ ] **Step 4: Run Electron tests**

Run: `npx vitest run apps/electron/tests/ipc.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add apps/electron/src/renderer/App.tsx apps/electron/src/renderer/index.html apps/electron/tests/ipc.test.ts
git commit -m "feat: add PDF checkbox to Electron sidebar"
```

---

### Task 6: Add printToPDF export handler in Electron main process

**Files:**
- Modify: `apps/electron/src/main.ts:84-122`

- [ ] **Step 1: Add `pdf` to filenames map in report:export handler**

In `apps/electron/src/main.ts`, in the `report:export` handler, change the `filenames` record from:

```ts
  const filenames: Record<keyof ExportPayload["outputs"], string> = {
    html: "report.html",
    markdown: "report.md",
    json: "findings.json",
    mermaid: "data-flow.mmd",
    sarif: "results.sarif",
    decision: "decision-record.json",
    remediation: "remediation-list.json"
  };
```

to:

```ts
  const filenames: Record<keyof ExportPayload["outputs"], string> = {
    html: "report.html",
    pdf: "report.pdf",
    markdown: "report.md",
    json: "findings.json",
    mermaid: "data-flow.mmd",
    sarif: "results.sarif",
    decision: "decision-record.json",
    remediation: "remediation-list.json"
  };
```

- [ ] **Step 2: Add printToPDF processing after file writing loop**

In `apps/electron/src/main.ts`, in the `report:export` handler, after the file writing loop (after `return { written };` is reached but before it), add the PDF post-processing. Insert this block **before** `if (payload.aiReview) {`:

```ts
  if (payload.outputs.pdf) {
    try {
      const pdfWin = new BrowserWindow({
        width: 1200,
        height: 900,
        show: false,
        webPreferences: { offscreen: true }
      });
      try {
        await pdfWin.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(payload.outputs.pdf)}`);
        const pdfBuffer = await pdfWin.webContents.printToPDF({
          pageSize: "A4",
          printBackground: true
        });
        const pdfDest = path.join(payload.outputDir, "report.pdf");
        await fs.writeFile(pdfDest, pdfBuffer);
        written.push(pdfDest);
      } finally {
        pdfWin.destroy();
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : "PDF export failed";
      console.error("printToPDF error:", msg);
    }
  }
```

The full `report:export` handler should now be:

```ts
ipcMain.handle("report:export", async (_event, payload: ExportPayload) => {
  assertAllowed("report:export");
  await fs.mkdir(payload.outputDir, { recursive: true });
  const written: string[] = [];
  const filenames: Record<keyof ExportPayload["outputs"], string> = {
    html: "report.html",
    pdf: "report.pdf",
    markdown: "report.md",
    json: "findings.json",
    mermaid: "data-flow.mmd",
    sarif: "results.sarif",
    decision: "decision-record.json",
    remediation: "remediation-list.json"
  };

  for (const [name, content] of Object.entries(payload.outputs)) {
    if (typeof content !== "string" || name === "pdf") {
      continue;
    }

    const destination = path.join(payload.outputDir, filenames[name as keyof typeof filenames]);
    await fs.writeFile(destination, content);
    written.push(destination);
  }

  if (payload.outputs.pdf) {
    try {
      const pdfWin = new BrowserWindow({
        width: 1200,
        height: 900,
        show: false,
        webPreferences: { offscreen: true }
      });
      try {
        await pdfWin.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(payload.outputs.pdf)}`);
        const pdfBuffer = await pdfWin.webContents.printToPDF({
          pageSize: "A4",
          printBackground: true
        });
        const pdfDest = path.join(payload.outputDir, "report.pdf");
        await fs.writeFile(pdfDest, pdfBuffer);
        written.push(pdfDest);
      } finally {
        pdfWin.destroy();
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : "PDF export failed";
      console.error("printToPDF error:", msg);
    }
  }

  if (payload.aiReview) {
    const jsonDest = path.join(payload.outputDir, "ai-review.json");
    await fs.writeFile(jsonDest, JSON.stringify(payload.aiReview, null, 2));
    written.push(jsonDest);

    const summary = payload.aiReview.summary;
    if (typeof summary === "string") {
      const mdDest = path.join(payload.outputDir, "ai-review.md");
      await fs.writeFile(mdDest, summary);
      written.push(mdDest);
    }
  }

  return { written };
});
```

Key detail: The file-writing loop now skips `name === "pdf"` to avoid writing raw HTML as `report.pdf`. The PDF is generated by the separate `printToPDF` block below.

- [ ] **Step 3: Run Electron IPC tests**

Run: `npx vitest run apps/electron/tests/ipc.test.ts`
Expected: PASS

- [ ] **Step 4: Run full test suite**

Run: `npm test`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add apps/electron/src/main.ts
git commit -m "feat: add printToPDF export handler in Electron main process"
```

---

### Task 7: Run full test suite and typecheck

**Files:**
- None (verification only)

- [ ] **Step 1: Run typecheck across all workspaces**

Run: `npx tsc --build --force`
Expected: No errors

- [ ] **Step 2: Run all tests**

Run: `npm test`
Expected: All tests pass (79+ tests)

- [ ] **Step 3: Verify no regressions**

Check that the test count did not decrease and no new failures appeared. If any test fails, investigate and fix before proceeding.

---

## Self-Review

**1. Spec coverage:**
- ✅ `"pdf"` added to `OutputFormat` union — Task 1
- ✅ `renderOutputs()` maps `"pdf"` to HTML — Task 2
- ✅ `@media print` CSS — Task 3
- ✅ CLI degradation warning — Task 4
- ✅ PDF checkbox in Electron sidebar — Task 5
- ✅ `printToPDF` in `report:export` handler — Task 6
- ✅ Filenames map includes `pdf: "report.pdf"` — Task 6
- ✅ Language follows UI selection (inherited from `renderHtmlReport`) — Task 2
- ✅ Error handling: try/catch/finally around hidden BrowserWindow — Task 6
- ✅ Tests for types, scan pipeline, CLI, IPC — Tasks 1-5

**2. Placeholder scan:** No TBD, TODO, or vague steps found.

**3. Type consistency:**
- `OutputFormat` includes `"pdf"` — used consistently in `types.ts`, `scan.ts`, `App.tsx`, CLI `index.ts`
- `ScanOutputName = OutputFormat | "decision" | "remediation"` — automatically picks up `"pdf"`
- `ExportPayload.outputs` uses `Partial<Record<OutputFormat | "decision" | "remediation", string>>` — `pdf` key works
- `outputFiles` in CLI includes `pdf: "report.pdf"` — matches filenames map in Electron
