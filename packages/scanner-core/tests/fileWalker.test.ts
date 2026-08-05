import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { listScannableFiles } from "../src/fileWalker.js";

describe("listScannableFiles", () => {
  it("includes python, go, and java files", async () => {
    const root = await createProject({
      "src/main.py": "import os\n",
      "src/main.go": "package main\n",
      "src/Main.java": "class Main {}\n",
      "src/index.ts": "console.log(1);\n"
    });

    const files = await listScannableFiles(root);

    expect(files).toEqual(expect.arrayContaining(["src/main.py", "src/main.go", "src/Main.java", "src/index.ts"]));
  });

  it("still excludes node_modules, dist, and .git", async () => {
    const root = await createProject({
      "node_modules/x/index.py": "import os\n",
      "dist/app.py": "x\n",
      ".git/config": "y\n",
      "src/main.py": "z\n"
    });

    const files = await listScannableFiles(root);

    expect(files).toEqual(["src/main.py"]);
  });
});

async function createProject(files: Record<string, string>): Promise<string> {
  const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "filewalker-test-"));
  await Promise.all(
    Object.entries(files).map(async ([filePath, content]) => {
      const fullPath = path.join(rootDir, filePath);
      await fs.mkdir(path.dirname(fullPath), { recursive: true });
      await fs.writeFile(fullPath, content);
    })
  );
  return rootDir;
}
