import { contextBridge, ipcRenderer } from "electron";

type AllowedIpcChannel =
  | "scan:start" | "scan:cancel"
  | "report:read" | "report:export"
  | "ai-review:run"
  | "ai-models:list"
  | "ai-connection:test"
  | "folder:open";

function invoke(channel: AllowedIpcChannel, payload?: unknown): Promise<unknown> {
  return ipcRenderer.invoke(channel, payload);
}

contextBridge.exposeInMainWorld("repoAuditor", {
  scanStart: (payload: unknown) => invoke("scan:start", payload),
  scanCancel: () => invoke("scan:cancel"),
  reportRead: (payload: unknown) => invoke("report:read", payload),
  reportExport: (payload: unknown) => invoke("report:export", payload),
  aiReviewRun: (payload: unknown) => invoke("ai-review:run", payload),
  aiModelsList: (payload: unknown) => invoke("ai-models:list", payload),
  aiConnectionTest: (payload: unknown) => invoke("ai-connection:test", payload),
  folderOpen: (payload: unknown) => invoke("folder:open", payload)
});
