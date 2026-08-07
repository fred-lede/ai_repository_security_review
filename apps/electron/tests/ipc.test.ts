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
      "source:read"
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
    expect(source).not.toContain("max-height: 55vh");
  });
});
