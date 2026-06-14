import { contextBridge, ipcRenderer } from "electron";
import { allowedIpcChannels, type AllowedIpcChannel } from "./ipc.js";

export { allowedIpcChannels };

function invoke(channel: AllowedIpcChannel, payload?: unknown): Promise<unknown> {
  return ipcRenderer.invoke(channel, payload);
}

contextBridge.exposeInMainWorld("repoAuditor", {
  scanStart: (payload: unknown) => invoke("scan:start", payload),
  scanCancel: () => invoke("scan:cancel"),
  reportRead: (payload: unknown) => invoke("report:read", payload),
  reportExport: (payload: unknown) => invoke("report:export", payload),
  aiReviewRun: (payload: unknown) => invoke("ai-review:run", payload),
  folderOpen: (payload: unknown) => invoke("folder:open", payload)
});
