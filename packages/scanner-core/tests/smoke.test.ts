import { describe, expect, it } from "vitest";
import { scannerCoreVersion } from "../src/index.js";

describe("scanner core", () => {
  it("exports a version", () => {
    expect(scannerCoreVersion).toBe("0.1.0");
  });
});
