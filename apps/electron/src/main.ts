import fs from "node:fs/promises";
import path from "node:path";
import { createOfflineAiReviewPlaceholder, runAiReview, type AiProviderConfig } from "@repo-auditor/ai-review";
import { scanTarget, type AuditReport, type NetworkPolicy, type OutputFormat } from "@repo-auditor/scanner-core";
import { app, BrowserWindow, dialog, ipcMain } from "electron";
import { isAllowedIpcChannel } from "./ipc.js";

interface ScanStartPayload {
  target: string;
  networkPolicy?: NetworkPolicy;
  outputFormats?: OutputFormat[];
}

interface ExportPayload {
  outputDir: string;
  outputs: Partial<Record<OutputFormat | "decision" | "remediation", string>>;
}

interface AiReviewPayload {
  report: AuditReport;
  provider: AiProviderConfig;
  execute?: boolean;
}

async function createWindow(): Promise<void> {
  const win = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 1080,
    minHeight: 720,
    title: "Repository Security Auditor",
    webPreferences: {
      preload: path.join(app.getAppPath(), "dist/preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });

  await win.loadFile(path.join(app.getAppPath(), "src/renderer/index.html"));
}

ipcMain.handle("scan:start", async (_event, payload: ScanStartPayload) => {
  assertAllowed("scan:start");
  if (!payload?.target || typeof payload.target !== "string") {
    throw new Error("A scan target is required");
  }

  return scanTarget(payload.target, {
    reviewMode: "full-audit",
    networkPolicy: payload.networkPolicy ?? "offline",
    outputFormats: payload.outputFormats ?? ["markdown", "json", "mermaid", "sarif"]
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
    markdown: "report.md",
    json: "findings.json",
    mermaid: "data-flow.mmd",
    sarif: "results.sarif",
    decision: "decision-record.json",
    remediation: "remediation-list.json"
  };

  for (const [name, content] of Object.entries(payload.outputs)) {
    if (typeof content !== "string") {
      continue;
    }

    const destination = path.join(payload.outputDir, filenames[name as keyof typeof filenames]);
    await fs.writeFile(destination, content);
    written.push(destination);
  }

  return { written };
});

ipcMain.handle("ai-review:run", async (_event, payload: AiReviewPayload) => {
  assertAllowed("ai-review:run");
  return payload.execute
    ? runAiReview(payload.report, payload.provider)
    : createOfflineAiReviewPlaceholder(payload.report, payload.provider);
});

ipcMain.handle("folder:open", async () => {
  assertAllowed("folder:open");
  const result = await dialog.showOpenDialog({
    properties: ["openDirectory", "openFile"],
    buttonLabel: "Select Target"
  });

  return { cancelled: result.canceled, paths: result.filePaths };
});

function assertAllowed(channel: string): void {
  if (!isAllowedIpcChannel(channel)) {
    throw new Error(`Blocked IPC channel: ${channel}`);
  }
}

await app.whenReady();
await createWindow();

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
