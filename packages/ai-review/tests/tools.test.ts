import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildTools, type ReviewToolContext } from "../src/tools.js";

const modeContext = (mode: "snippets" | "full-files", allowedFiles?: string[]): ReviewToolContext => ({
  scanPath: "",
  mode,
  allowedFiles
});

describe("buildTools", () => {
  it("exposes only file_read in snippets mode", () => {
    const tools = buildTools("finding-snippets", modeContext("snippets", ["src/index.ts"]));
    expect(tools.map((t) => t.name)).toEqual(["file_read"]);
  });

  it("exposes all tools in full-files mode", () => {
    const tools = buildTools("full-files", modeContext("full-files"));
    expect(tools.map((t) => t.name)).toEqual(["file_read", "file_find", "code_search"]);
  });

  it("exposes no tools in metadata-only mode", () => {
    const tools = buildTools("metadata-only", modeContext("snippets"));
    expect(tools).toEqual([]);
  });
});

describe("review tools", () => {
  async function project(): Promise<{ root: string; ctx: ReviewToolContext }> {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "tools-test-"));
    await fs.mkdir(path.join(root, "src"), { recursive: true });
    await fs.writeFile(path.join(root, "src", "index.ts"), "const token = process.env.SECRET;\n");
    await fs.writeFile(path.join(root, "src", "auth.py"), "import os\nos.system('whoami')\n");
    return { root, ctx: { scanPath: root, mode: "full-files" } };
  }

  it("file_read returns numbered lines for a file", async () => {
    const { root, ctx } = await project();
    const [fileRead] = buildTools("full-files", ctx);
    const result = await fileRead.run({ path: "src/auth.py" }, ctx);
    expect(result).toContain("1\timport os");
    expect(result).toContain("os.system('whoami')");
  });

  it("file_read rejects paths escaping the scan directory", async () => {
    const { root, ctx } = await project();
    const [fileRead] = buildTools("full-files", ctx);
    await expect(fileRead.run({ path: "../secret.txt" }, ctx)).rejects.toThrow("escapes");
  });

  it("file_read in snippets mode rejects files not in allowedFiles", async () => {
    const { root } = await project();
    const ctx: ReviewToolContext = { scanPath: root, mode: "snippets", allowedFiles: ["src/index.ts"] };
    const [fileRead] = buildTools("finding-snippets", ctx);
    await expect(fileRead.run({ path: "src/auth.py" }, ctx)).rejects.toThrow("not allowed");
    const allowed = await fileRead.run({ path: "src/index.ts" }, ctx);
    expect(allowed).toContain("SECRET");
  });

  it("code_search finds matching lines", async () => {
    const { root, ctx } = await project();
    const tools = buildTools("full-files", ctx);
    const search = tools.find((t) => t.name === "code_search")!;
    const result = await search.run({ query: "os\\.system" }, ctx);
    expect(result).toContain("src/auth.py:2");
  });

  it("file_find matches glob patterns", async () => {
    const { root, ctx } = await project();
    const tools = buildTools("full-files", ctx);
    const find = tools.find((t) => t.name === "file_find")!;
    const result = await find.run({ pattern: "**/*.py" }, ctx);
    expect(result).toContain("src/auth.py");
  });
});
