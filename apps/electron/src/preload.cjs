const { contextBridge, ipcRenderer } = require("electron");

function invoke(channel, payload) {
  return ipcRenderer.invoke(channel, payload);
}

contextBridge.exposeInMainWorld("repoAuditor", {
  scanStart: (payload) => invoke("scan:start", payload),
  scanCancel: () => invoke("scan:cancel"),
  reportRead: (payload) => invoke("report:read", payload),
  reportExport: (payload) => invoke("report:export", payload),
  aiReviewRun: (payload) => invoke("ai-review:run", payload),
  aiModelsList: (payload) => invoke("ai-models:list", payload),
  aiConnectionTest: (payload) => invoke("ai-connection:test", payload),
  folderOpen: (payload) => invoke("folder:open", payload),
  rulesLoad: () => invoke("rules:load"),
  rulesSave: (payload) => invoke("rules:save", payload),
  keySave: (payload) => invoke("key:save", payload),
  keyLoad: () => invoke("key:load"),
  keyDelete: () => invoke("key:delete")
});
