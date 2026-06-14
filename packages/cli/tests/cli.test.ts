import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { createProgram } from "../src/index.js";

describe("repo-auditor cli", () => {
  it("creates a production program with default IO", () => {
    expect(createProgram().name()).toBe("repo-auditor");
  });

  it("writes reports and returns a blocking decision for the malicious fixture", async () => {
    const outputDir = await fs.mkdtemp(path.join(os.tmpdir(), "repo-auditor-cli-"));
    const exitCodes: number[] = [];
    const program = createProgram({
      writeOut: (value) => output.push(value),
      setExitCode: (code) => exitCodes.push(code)
    });
    const output: string[] = [];
    program.exitOverride();

    await program.parseAsync(
      [
        "node",
        "repo-auditor",
        "scan",
        path.resolve("fixtures/malicious-package"),
        "--offline",
        "--format",
        "markdown,json,mermaid,sarif",
        "--output",
        outputDir
      ],
      { from: "node" }
    );

    await expect(fs.stat(path.join(outputDir, "report.md"))).resolves.toBeDefined();
    await expect(fs.stat(path.join(outputDir, "findings.json"))).resolves.toBeDefined();
    await expect(fs.stat(path.join(outputDir, "data-flow.mmd"))).resolves.toBeDefined();
    await expect(fs.stat(path.join(outputDir, "results.sarif"))).resolves.toBeDefined();
    await expect(fs.stat(path.join(outputDir, "decision-record.json"))).resolves.toBeDefined();
    await expect(fs.stat(path.join(outputDir, "remediation-list.json"))).resolves.toBeDefined();
    expect(output.join("")).toContain("Decision: Block");
    expect(exitCodes).toEqual([2]);
  });

  it("rejects unsupported output formats", async () => {
    const program = createProgram();
    program.exitOverride();

    await expect(
      program.parseAsync(["node", "repo-auditor", "scan", "fixtures/benign-package", "--format", "xml"], {
        from: "node"
      })
    ).rejects.toThrow("Unsupported output format: xml");
  });
});
