import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { createProgram, type CliIo } from "../src/index.js";
import { loadBenchSpec, runBench, type BenchSpec } from "../src/bench.js";

const repoFixtures = (name: string) => path.join(__dirname, "..", "..", "..", "fixtures", name);

function cliIo(): CliIo & { out: string[] } {
  const out: string[] = [];
  return {
    out,
    writeOut: (value) => out.push(value),
    setExitCode: () => {}
  };
}

async function writeSpec(dir: string, spec: BenchSpec): Promise<string> {
  const specPath = path.join(dir, "benchmarks.json");
  await fs.writeFile(specPath, JSON.stringify(spec, null, 2));
  return specPath;
}

const maliciousExpectations = [
  { category: "postinstall-script", filePath: "package.json", lineStart: 1, lineEnd: 1 },
  { category: "supply-chain", filePath: "package.json", lineStart: 1, lineEnd: 1 },
  { category: "command-injection", filePath: "src/index.ts", lineStart: 13, lineEnd: 13 },
  { category: "network", filePath: "src/index.ts", lineStart: 9, lineEnd: 9 },
  { category: "network", filePath: "src/index.ts", lineStart: 13, lineEnd: 13 }
];

describe("loadBenchSpec", () => {
  it("resolves case targets relative to the spec file directory", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "bench-spec-"));
    const specPath = await writeSpec(root, {
      cases: [{ name: "t", target: "../fixtures-relative", expected: [] }]
    });
    const spec = await loadBenchSpec(specPath);
    expect(spec.cases[0].target).toBe(path.join(path.dirname(specPath), "../fixtures-relative"));
  });

  it("rejects a spec without cases", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "bench-spec-"));
    const specPath = await writeSpec(root, { cases: [] } as BenchSpec);
    await expect(loadBenchSpec(specPath)).rejects.toThrow(/cases/i);
  });
});

describe("runBench", () => {
  it("scores a perfect run against the malicious fixture", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "bench-run-"));
    const specPath = await writeSpec(root, {
      cases: [
        {
          name: "malicious-package",
          target: repoFixtures("malicious-package"),
          expected: maliciousExpectations
        }
      ]
    });
    const io = cliIo();
    const report = await runBench(specPath, path.join(root, "out"), io);
    const testCase = report.cases[0];
    expect(testCase.metrics.precision).toBe(1);
    expect(testCase.metrics.recall).toBe(1);
    expect(report.aggregate.f1).toBe(1);
    await fs.access(path.join(root, "out", "benchmark-report.json"));
    const markdown = await fs.readFile(path.join(root, "out", "benchmark-report.md"), "utf8");
    expect(markdown).toContain("Precision");
  });

  it("scores a vacuous-perfect run for a benign case", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "bench-run-"));
    const specPath = await writeSpec(root, {
      cases: [
        {
          name: "benign-package",
          target: repoFixtures("benign-package"),
          expected: []
        }
      ]
    });
    const io = cliIo();
    const report = await runBench(specPath, path.join(root, "out"), io);
    expect(report.cases[0].metrics).toEqual({ tp: 0, fp: 0, fn: 0, precision: 1, recall: 1, f1: 1 });
  });

  it("runs end to end through the CLI program", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "bench-e2e-"));
    const specPath = await writeSpec(root, {
      cases: [
        {
          name: "benign-package",
          target: repoFixtures("benign-package"),
          expected: []
        }
      ]
    });
    const io = cliIo();
    const program = createProgram(io);
    await program.parseAsync(["node", "repo-auditor", "bench", "--spec", specPath, "--output", path.join(root, "out")]);
    expect(io.out.join("")).toContain("precision=");
    expect(io.out.join("")).toContain("Aggregate:");
    await fs.access(path.join(root, "out", "benchmark-report.md"));
  });
});
