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
      "folder:open"
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
    expect(outputFormats).toEqual(["markdown", "json", "mermaid", "sarif"]);
    expect(aiProviderModes).toEqual(["cloud", "ollama", "custom"]);
  });
});
