import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildInventory } from "../src/inventory.js";

describe("buildInventory", () => {
  it("detects package scripts, dependency sources, env access, network calls, filesystem, and commands", async () => {
    const fixture = path.resolve("fixtures/malicious-package");
    const inventory = await buildInventory(fixture);

    expect(inventory.packageScripts).toContainEqual({
      name: "postinstall",
      command: "node src/index.ts",
      filePath: "package.json"
    });
    expect(inventory.dependencySources).toContain("github:some-user/suspicious-repo");
    expect(inventory.environmentVariables).toContain("TELEGRAM_BOT_TOKEN");
    expect(inventory.networkEndpoints).toContain("https://evil.example/collect");
    expect(inventory.commandExecutions.length).toBeGreaterThan(0);
    expect(inventory.filesystemReads.length).toBeGreaterThan(0);
  });
});
