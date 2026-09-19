import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { allowedIpcChannels, isAllowedIpcChannel } from "../src/ipc.js";
import { inputModes, outputFormats, aiProviderModes } from "../src/renderer/App.js";

describe("Electron IPC allowlist", () => {
  it("exposes only intended channels", () => {
    expect(allowedIpcChannels).toEqual([
      "scan:start",
      "scan:cancel",
      "report:read",
      "report:export",
      "ai-review:run",
      "finding:review",
      "ai-review:progress",
      "ai-models:list",
      "ai-connection:test",
      "folder:open",
      "rules:load",
      "rules:save",
      "key:save",
      "key:load",
      "key:delete",
      "source:read",
      "session:list"
    ]);
  });

  it("rejects unknown channels", () => {
    expect(isAllowedIpcChannel("scan:start")).toBe(true);
    expect(isAllowedIpcChannel("shell:exec")).toBe(false);
  });
});

describe("renderer shell options", () => {
  it("includes all expected input, output, and AI provider modes", () => {
    expect(inputModes).toEqual(["Local Directory", "File", "GitHub Repository", "npm Package"]);
    expect(outputFormats).toEqual(["markdown", "json", "mermaid", "sarif", "html", "pdf"]);
    expect(aiProviderModes).toEqual(["cloud", "ollama", "custom"]);
  });

  it("uses a persisted model picker with provider model detection", () => {
    const source = fs.readFileSync(path.join(__dirname, "../src/renderer/index.html"), "utf8");

    expect(source).toContain('const settingsKey = "repo-auditor.ai-settings"');
    expect(source).toContain('<select id="provider-model"');
    expect(source).not.toContain('<input id="provider-model"');
    expect(source).toContain('id="refresh-models"');
    expect(source).toContain('id="provider-api-key"');
    expect(source).toContain("window.repoAuditor.aiModelsList");
    expect(source).toContain("localStorage.setItem(settingsKey");
    expect(source).not.toContain("apiKey: settings.apiKey");
  });
});

describe("main window lifecycle", () => {
  it("keeps a module-level BrowserWindow reference so packaged macOS builds show a window", () => {
    const source = fs.readFileSync(path.join(__dirname, "../src/main.ts"), "utf8");

    expect(source).toContain("let mainWindow: BrowserWindow | undefined");
    expect(source).toContain("mainWindow = new BrowserWindow");
    expect(source).toContain('mainWindow.on("closed"');
    expect(source).toContain("void app.whenReady().then(createWindow)");
    expect(source).not.toContain("await app.whenReady()");
  });

  it("lazy-loads audit engines after the desktop window can initialize", () => {
    const source = fs.readFileSync(path.join(__dirname, "../src/main.ts"), "utf8");

    expect(source).toContain('await import("@repo-auditor/scanner-core")');
    expect(source).toContain('await import("@repo-auditor/ai-review")');
    expect(source).not.toContain('import { scanTarget');
    expect(source).not.toContain('import { createOfflineAiReviewPlaceholder');
  });

  it("passes the resolved target path to the AI review agent", () => {
    const source = fs.readFileSync(path.join(__dirname, "../src/main.ts"), "utf8");

    expect(source).toContain('runAiReview(payload.report, provider, {');
    expect(source).toContain('scanPath: payload.report.target.localPath ?? undefined');
  });

  it("keeps ai-review:run in the IPC allowlist", () => {
    expect(isAllowedIpcChannel("ai-review:run")).toBe(true);
  });

  it("regenerates report outputs from the merged AI report so preview and export are not stale", () => {
    const source = fs.readFileSync(path.join(__dirname, "../src/main.ts"), "utf8");

    expect(source).toContain("renderOutputs(mergedReport");
    expect(source).toContain("mergedOutputs");
  });

  it("uses merged outputs in the renderer instead of nulling them (regression: outputs undefined)", () => {
    const source = fs.readFileSync(path.join(__dirname, "../src/renderer/index.html"), "utf8");

    expect(source).toContain("outputs: state.aiReview.mergedOutputs");
    expect(source).not.toContain("outputs: undefined");
    expect(source).toMatch(/result\.outputs\?\.markdown/);
  });

  it("keeps clipboard shortcuts working via an Edit menu", () => {
    const source = fs.readFileSync(path.join(__dirname, "../src/main.ts"), "utf8");

    expect(source).toMatch(/{ role: "cut" /);
    expect(source).toMatch(/{ role: "copy" /);
    expect(source).toMatch(/{ role: "paste" /);
    expect(source).toMatch(/{ role: "selectAll" /);
  });

  it("keeps finding:review in the IPC allowlist", () => {
    expect(isAllowedIpcChannel("finding:review")).toBe(true);
  });

  it("registers the finding:review handler and lazy-loads runDeepDive", () => {
    const source = fs.readFileSync(path.join(__dirname, "../src/main.ts"), "utf8");

    expect(source).toContain('ipcMain.handle("finding:review"');
    expect(source).toContain('assertAllowed("finding:review")');
    expect(source).toContain("runDeepDive(");
    expect(source).toContain("scanPath: payload.report.target.localPath ?? undefined");
  });

  it("adds per-finding deep-dive controls to the renderer", () => {
    const source = fs.readFileSync(path.join(__dirname, "../src/renderer/index.html"), "utf8");

    expect(source).toContain("window.repoAuditor.findingReview");
    expect(source).toContain('t("aiDeepDive")');
    expect(source).toContain("aiVerdictReal");
    expect(source).toContain('dotsSpan.className = "dots"');
    expect(source).toContain("@keyframes dots");
  });

  it("exposes findingReview on the runtime preload bridge", () => {
    const source = fs.readFileSync(path.join(__dirname, "../src/preload.cjs"), "utf8");

    expect(source).toContain('findingReview: (payload) => invoke("finding:review", payload)');
  });
});

describe("renderer findings layout", () => {
  it("lets the findings list track the window height and scroll internally", () => {
    const source = fs.readFileSync(path.join(__dirname, "../src/renderer/index.html"), "utf8");

    expect(source).toMatch(/main\s*{[^}]*height:\s*100vh/s);
    expect(source).toMatch(/main\s*{[^}]*overflow:\s*hidden/s);
    expect(source).toMatch(/\.findings\s*{[^}]*flex:\s*1/s);
    expect(source).toMatch(/\.findings\s*{[^}]*min-height:\s*0/s);
    expect(source).toMatch(/\.findings\s*{[^}]*overflow:\s*auto/s);
    expect(source).toMatch(/\.findings\s*{[^}]*grid-auto-rows:\s*max-content/s);
    expect(source).not.toContain("max-height: 55vh");
  });

  it("sizes finding rows to their content so cards grow when details expand", () => {
    const source = fs.readFileSync(path.join(__dirname, "../src/renderer/index.html"), "utf8");

    expect(source).toMatch(/\.findings\s*{[^}]*grid-auto-rows:\s*max-content/s);
  });

  it("scrolls revealed source context into view", () => {
    const source = fs.readFileSync(path.join(__dirname, "../src/renderer/index.html"), "utf8");

    expect(source).toMatch(/pre\.scrollIntoView\(\{\s*block:\s*"nearest"\s*\}\)/);
  });

  it("keeps finding cards within the list width so long context lines scroll inside the code block", () => {
    const source = fs.readFileSync(path.join(__dirname, "../src/renderer/index.html"), "utf8");

    expect(source).toMatch(/\.finding\s*{[^}]*min-width:\s*0/s);
  });
});

describe("renderer export button", () => {
  it("does not duplicate the Decision heading at the top", () => {
    const source = fs.readFileSync(path.join(__dirname, "../src/renderer/index.html"), "utf8");

    expect(source).not.toMatch(/data-i18n="decision"/);
    expect(source).toContain('<strong id="decision">');
  });

  it("groups the export button and status under Prepare AI Review in the sidebar", () => {
    const source = fs.readFileSync(path.join(__dirname, "../src/renderer/index.html"), "utf8");

    expect(source).toMatch(/id="ai-review"[^>]*>[\s\S]*?<button id="export" class="secondary" data-i18n="exportReports">[\s\S]*?<div id="export-status">/);
    expect(source).not.toContain("section-footer");
  });
});

describe("AI review sessions", () => {
  it("allows session:list in the IPC allowlist", () => {
    expect(isAllowedIpcChannel("session:list")).toBe(true);
  });

  it("registers a session:list handler bound to the sessions directory", () => {
    const source = fs.readFileSync(path.join(__dirname, "../src/main.ts"), "utf8");

    expect(source).toMatch(/ipcMain\.handle\("session:list"/);
    expect(source).toMatch(/listSessions\(sessionsDir\)/);
    expect(source).toMatch(/sessionsDir = path\.join\(app\.getPath\("userData"\), "sessions"\)/);
  });

  it("passes sessionDir and resumeSessionId into ai-review:run", () => {
    const source = fs.readFileSync(path.join(__dirname, "../src/main.ts"), "utf8");

    expect(source).toMatch(/sessionDir: sessionsDir/);
    expect(source).toMatch(/resumeSessionId: payload\.resumeSessionId/);
    expect(source).toMatch(/resumeSessionId\?: string;/);
  });

  it("exposes sessionList on the preload bridge", () => {
    const source = fs.readFileSync(path.join(__dirname, "../src/preload.cjs"), "utf8");

    expect(source).toContain("sessionList: () => invoke(\"session:list\")");
  });

  it("renders a sessions list with a resume action in the sidebar", () => {
    const source = fs.readFileSync(path.join(__dirname, "../src/renderer/index.html"), "utf8");

    expect(source).toMatch(/<div id="sessions" class="muted" hidden>/);
    expect(source).toMatch(/function refreshSessions\(\)/);
    expect(source).toMatch(/window\.repoAuditor\.sessionList\(\)/);
    expect(source).toMatch(/resumeSessionId/);
    expect(source).toMatch(/data-session-id/);
  });

  it("localizes the sessions UI in all three languages", () => {
    const source = fs.readFileSync(path.join(__dirname, "../src/renderer/index.html"), "utf8");

    expect(source).toContain('sessionsTitle: "Sessions"');
    expect(source).toContain('sessionsTitle: "工作階段"');
    expect(source).toContain('sessionsTitle: "会话"');
    expect(source).toContain('resume: "續跑"');
    expect(source).toContain('resume: "续跑"');
  });

  it("disables resume buttons until a scan has run", () => {
    const source = fs.readFileSync(path.join(__dirname, "../src/renderer/index.html"), "utf8");

    expect(source).toMatch(/if \(!state\.result\) \{\s*resumeBtn\.disabled = true;\s*resumeBtn\.title = t\("noScanToResume"\);\s*\}/);
    expect(source).toContain('noScanToResume: "Run a scan first before resuming"');
  });
});

describe("AI review report preview extras", () => {
  const readRenderer = () => fs.readFileSync(path.join(__dirname, "../src/renderer/index.html"), "utf8");

  it("renders coverage with covered/total and skipped batches", () => {
    const source = readRenderer();

    expect(source).toMatch(/t\("aiCoverage"\)\}: \$\{coverage\.covered\.length\}\/\$\{coverage\.total\}/);
    expect(source).toMatch(/t\("aiBatchesSkipped"\)\}: \$\{coverage\.skippedBatches\}/);
  });

  it("renders the resume state on the status line", () => {
    const source = readRenderer();

    expect(source).toMatch(/aiReview\.resumedFromSession \? ` \(\$\{t\("aiResumedFromSession"\)\}\)`/);
  });

  it("renders a reflections section with localized verdicts", () => {
    const source = readRenderer();

    expect(source).toMatch(/## \$\{t\("aiReflections"\)\}/);
    expect(source).toMatch(/t\("aiReflectionVerdict"\)\}: \$\{localizedVerdict\(reflection\.verdict\)\}/);
    expect(source).toContain("const reflectionVerdictLabels = {");
  });

  it("localizes the extras in all three languages", () => {
    const source = readRenderer();

    expect(source).toContain('aiResumedFromSession: "resumed from session"');
    expect(source).toContain('aiResumedFromSession: "自工作階段續跑"');
    expect(source).toContain('aiResumedFromSession: "自会话续跑"');
    expect(source).toContain('aiReflections: "AI 反思"');
    expect(source).toContain('aiReflections: "AI 反思"');
    expect(source).toContain('aiCoverage: "AI 覆蓋度"');
    expect(source).toContain('aiCoverage: "AI 覆盖度"');
  });
});
