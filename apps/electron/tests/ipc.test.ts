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
      "ai-models:list",
      "ai-connection:test",
      "folder:open",
      "rules:load",
      "rules:save",
      "key:save",
      "key:load",
      "key:delete"
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
});
