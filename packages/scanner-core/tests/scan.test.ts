import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildInventory, scanTarget } from "../src/index.js";

describe("scan orchestration", () => {
  it("runs the full scanner pipeline and renders requested outputs", async () => {
    const result = await scanTarget(path.resolve("fixtures/malicious-package"), {
      reviewMode: "full-audit",
      networkPolicy: "offline",
      outputFormats: ["markdown", "json", "mermaid", "sarif"]
    });

    expect(result.report.risk.decision).toBe("Block");
    expect(result.outputs.markdown).toContain("Repository Security Audit Report");
    expect(JSON.parse(result.outputs.json ?? "{}")).toEqual(
      expect.objectContaining({
        risk: expect.objectContaining({ decision: "Block" })
      })
    );
    expect(result.outputs.mermaid).toContain("flowchart LR");
    expect(JSON.parse(result.outputs.sarif ?? "{}")).toEqual(
      expect.objectContaining({
        version: "2.1.0"
      })
    );
    expect(JSON.parse(result.outputs.decision ?? "{}")).toEqual(
      expect.objectContaining({
        decision: "Block"
      })
    );
    expect(JSON.parse(result.outputs.remediation ?? "[]")).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          decisionRequired: true
        })
      ])
    );
  });

  it("rejects unresolved remote targets before inventory building", async () => {
    await expect(
      scanTarget("https://github.com/grinev/opencode-telegram-bot.git", {
        reviewMode: "full-audit",
        networkPolicy: "online",
        outputFormats: ["json"]
      })
    ).rejects.toThrow("Remote acquisition is not implemented yet");
  });

  it("can inventory a single local source file", async () => {
    const inventory = await buildInventory(path.resolve("fixtures/malicious-package/src/index.ts"));

    expect(inventory.files).toEqual(["index.ts"]);
    expect(inventory.networkEndpoints).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          endpoint: "https://evil.example/collect"
        })
      ])
    );
  });
});
