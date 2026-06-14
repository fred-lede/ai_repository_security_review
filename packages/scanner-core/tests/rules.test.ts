import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildInventory } from "../src/inventory.js";
import { runRules } from "../src/rules.js";

describe("runRules", () => {
  it("creates findings for postinstall, command execution, exfiltration candidates, and risky dependencies", async () => {
    const root = path.resolve("fixtures/malicious-package");
    const inventory = await buildInventory(root);
    const findings = runRules(inventory);

    expect(findings.some((finding) => finding.category === "postinstall-script")).toBe(true);
    expect(findings.some((finding) => finding.category === "command-injection")).toBe(true);
    expect(findings.some((finding) => finding.category === "data-exfiltration")).toBe(true);
    expect(findings.some((finding) => finding.category === "supply-chain")).toBe(true);
  });
});
