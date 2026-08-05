import { describe, expect, it } from "vitest";
import { matchesGlob } from "../src/glob.js";

describe("matchesGlob", () => {
  it("matches **/*.ext across directories", () => {
    expect(matchesGlob("**/*.py", "src/main.py")).toBe(true);
    expect(matchesGlob("**/*.py", "main.py")).toBe(true);
    expect(matchesGlob("**/*.py", "src/main.txt")).toBe(false);
  });

  it("matches **/name patterns", () => {
    expect(matchesGlob("**/Dockerfile*", "Dockerfile")).toBe(true);
    expect(matchesGlob("**/Dockerfile*", "docker/Dockerfile.dev")).toBe(true);
    expect(matchesGlob("**/Dockerfile*", "src/index.ts")).toBe(false);
  });

  it("matches brace groups", () => {
    expect(matchesGlob("**/*.{js,jsx}", "src/app.jsx")).toBe(true);
    expect(matchesGlob("**/*.{js,jsx}", "src/app.json")).toBe(false);
  });

  it("matches directory-prefixed patterns", () => {
    expect(matchesGlob(".github/workflows/**", ".github/workflows/ci.yml")).toBe(true);
    expect(matchesGlob(".github/workflows/**", ".github/ci.yml")).toBe(false);
  });
});
