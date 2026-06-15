import fs from "node:fs/promises";
import path from "node:path";
import type { AiProviderConfig } from "@repo-auditor/ai-review";
import type { AuditReport, Language, NetworkPolicy, OutputFormat } from "@repo-auditor/scanner-core";
import { app, BrowserWindow, dialog, ipcMain, safeStorage } from "electron";
import { isAllowedIpcChannel } from "./ipc.js";

interface ScanStartPayload {
  target: string;
  networkPolicy?: NetworkPolicy;
  outputFormats?: OutputFormat[];
  language?: Language;
}

interface ExportPayload {
  outputDir: string;
  outputs: Partial<Record<OutputFormat | "decision" | "remediation", string>>;
  aiReview?: Record<string, unknown>;
}

interface AiReviewPayload {
  report: AuditReport;
  provider: AiProviderConfig;
  execute?: boolean;
}

interface AiModelsPayload {
  provider: Pick<AiProviderConfig, "type" | "baseUrl" | "apiKey">;
}

let mainWindow: BrowserWindow | undefined;

async function createWindow(): Promise<void> {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 1080,
    minHeight: 720,
    title: "Repository Security Auditor",
    icon: path.join(app.getAppPath(), "assets/icon.png"),
    webPreferences: {
      preload: path.join(app.getAppPath(), "build/preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });

  mainWindow.on("closed", () => {
    mainWindow = undefined;
  });

  await mainWindow.loadFile(path.join(app.getAppPath(), "src/renderer/index.html"));
}

ipcMain.handle("scan:start", async (_event, payload: ScanStartPayload) => {
  assertAllowed("scan:start");
  if (!payload?.target || typeof payload.target !== "string") {
    throw new Error("A scan target is required");
  }

  const { scanTarget } = await import("@repo-auditor/scanner-core");
  const { loadExternalRules } = await import("@repo-auditor/scanner-core");
  const extraRules = await loadExternalRules(app.getPath("userData"));
  return scanTarget(payload.target, {
    reviewMode: "full-audit",
    networkPolicy: payload.networkPolicy ?? "online",
    outputFormats: payload.outputFormats ?? ["markdown", "json", "mermaid", "sarif"],
    language: payload.language ?? "zh-TW",
    extraRules
  });
});

ipcMain.handle("scan:cancel", async () => {
  assertAllowed("scan:cancel");
  return { cancelled: true };
});

ipcMain.handle("report:read", async (_event, payload: { filePath: string }) => {
  assertAllowed("report:read");
  return fs.readFile(payload.filePath, "utf8");
});

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

ipcMain.handle("ai-review:run", async (_event, payload: AiReviewPayload) => {
  assertAllowed("ai-review:run");
  const { createOfflineAiReviewPlaceholder, runAiReview } = await import("@repo-auditor/ai-review");
  const provider = {
    ...payload.provider,
    language: payload.provider.language ?? "zh-TW"
  };
  return payload.execute
    ? runAiReview(payload.report, provider)
    : createOfflineAiReviewPlaceholder(payload.report, provider);
});

ipcMain.handle("ai-models:list", async (_event, payload: AiModelsPayload) => {
  assertAllowed("ai-models:list");
  const provider = payload?.provider;
  if (!provider || !["cloud", "ollama", "custom"].includes(provider.type) || typeof provider.baseUrl !== "string") {
    throw new Error("A valid AI provider is required");
  }

  const { listProviderModels } = await import("@repo-auditor/ai-review");
  return listProviderModels({
    type: provider.type,
    baseUrl: provider.baseUrl,
    apiKey: provider.apiKey,
    timeoutMs: 5000
  });
});

ipcMain.handle("ai-connection:test", async (_event, payload: { provider: Pick<AiProviderConfig, "type" | "baseUrl" | "apiKey"> }) => {
  assertAllowed("ai-connection:test");
  const provider = payload?.provider;
  if (!provider || typeof provider.baseUrl !== "string") {
    return { ok: false, error: "A valid provider configuration is required" };
  }

  const baseUrl = provider.baseUrl.replace(/\/$/, "");
  const testUrl = provider.type === "ollama" ? `${baseUrl}/api/tags` : `${baseUrl}/models`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const response = await fetch(testUrl, {
      method: "GET",
      headers: {
        "content-type": "application/json",
        ...(provider.type !== "ollama" && provider.apiKey ? { authorization: `Bearer ${provider.apiKey}` } : {})
      },
      signal: controller.signal
    });
    clearTimeout(timeout);
    return { ok: true, status: response.status };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error.message : "Connection failed"
    };
  }
});

ipcMain.handle("folder:open", async () => {
  assertAllowed("folder:open");
  const result = await dialog.showOpenDialog({
    properties: ["openDirectory", "openFile"],
    buttonLabel: "Select Target"
  });

  return { cancelled: result.canceled, paths: result.filePaths };
});

ipcMain.handle("rules:load", async () => {
  assertAllowed("rules:load");
  const { loadExternalRules } = await import("@repo-auditor/scanner-core");
  return loadExternalRules(app.getPath("userData"));
});

ipcMain.handle("rules:save", async (_event, payload: import("@repo-auditor/scanner-core").RuleDefinition[]) => {
  assertAllowed("rules:save");
  const { saveExternalRules } = await import("@repo-auditor/scanner-core");
  await saveExternalRules(payload, app.getPath("userData"));
  return { ok: true };
});

const keyFilePath = path.join(app.getPath("userData"), "repo-auditor-key.enc");

ipcMain.handle("key:save", async (_event, payload: { apiKey: string }) => {
  assertAllowed("key:save");
  if (!safeStorage.isEncryptionAvailable()) {
    return { ok: false, error: "OS-level encryption is not available on this system." };
  }
  const encrypted = safeStorage.encryptString(payload.apiKey);
  await fs.writeFile(keyFilePath, encrypted);
  return { ok: true };
});

ipcMain.handle("key:load", async () => {
  assertAllowed("key:load");
  if (!safeStorage.isEncryptionAvailable()) {
    return { ok: false, error: "OS-level encryption is not available on this system." };
  }
  try {
    const encrypted = await fs.readFile(keyFilePath);
    const apiKey = safeStorage.decryptString(encrypted);
    return { ok: true, apiKey };
  } catch {
    return { ok: true, apiKey: "" };
  }
});

ipcMain.handle("key:delete", async () => {
  assertAllowed("key:delete");
  try {
    await fs.unlink(keyFilePath);
  } catch { /* file may not exist */ }
  return { ok: true };
});

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
    const lines = allLines.slice(start - 1, end).map((text, i) => ({
      num: start + i,
      text
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

function assertAllowed(channel: string): void {
  if (!isAllowedIpcChannel(channel)) {
    throw new Error(`Blocked IPC channel: ${channel}`);
  }
}

void app.whenReady().then(createWindow);

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    void createWindow();
  }
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});
