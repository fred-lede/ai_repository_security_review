import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { resolveTarget } from "../src/targetResolver.js";
import type { ScanOptions } from "../src/types.js";

describe("resolveTarget", () => {
  const scanOptions: ScanOptions = {
    reviewMode: "full-audit",
    networkPolicy: "online",
    outputFormats: ["json"]
  };

  it("resolves local directories without network", async () => {
    const fixturePath = path.resolve("fixtures/benign-package");
    const target = await resolveTarget(fixturePath, {
      reviewMode: "full-audit",
      networkPolicy: "offline",
      outputFormats: ["json"]
    });

    expect(target.type).toBe("local-directory");
    expect(target.localPath).toBe(fixturePath);
    expect(target.networkUsed).toBe(false);
    expect(target.trustBoundary).toBe("local");
  });

  it("prefers existing local files that look like npm specs when network is disabled", async () => {
    const originalCwd = process.cwd();
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "resolver-target-"));
    const packageLikeFile = path.join(tempDir, "left-pad@1.3.0");
    await fs.writeFile(packageLikeFile, "{}");

    try {
      process.chdir(tempDir);

      const target = await resolveTarget("left-pad@1.3.0", {
        reviewMode: "full-audit",
        networkPolicy: "no-network",
        outputFormats: ["json"]
      });

      expect(target.type).toBe("local-file");
      expect(target.localPath).toBe(path.resolve("left-pad@1.3.0"));
      expect(target.networkUsed).toBe(false);
      expect(target.trustBoundary).toBe("local");
    } finally {
      process.chdir(originalCwd);
      await fs.rm(tempDir, { force: true, recursive: true });
    }
  });

  it("prefers existing local directories that look like npm specs when network is disabled", async () => {
    const originalCwd = process.cwd();
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "resolver-target-"));
    const packageLikeDir = path.join(tempDir, "left-pad@1.3.0");
    await fs.mkdir(packageLikeDir);

    try {
      process.chdir(tempDir);

      const target = await resolveTarget("left-pad@1.3.0", {
        reviewMode: "full-audit",
        networkPolicy: "no-network",
        outputFormats: ["json"]
      });

      expect(target.type).toBe("local-directory");
      expect(target.localPath).toBe(path.resolve("left-pad@1.3.0"));
      expect(target.networkUsed).toBe(false);
      expect(target.trustBoundary).toBe("local");
    } finally {
      process.chdir(originalCwd);
      await fs.rm(tempDir, { force: true, recursive: true });
    }
  });

  it("rejects remote targets when network is disabled", async () => {
    await expect(
      resolveTarget("https://github.com/grinev/opencode-telegram-bot", {
        reviewMode: "full-audit",
        networkPolicy: "no-network",
        outputFormats: ["json"]
      })
    ).rejects.toThrow("Network access is disabled");
  });

  it("rejects npm package specs when network is disabled", async () => {
    for (const networkPolicy of ["no-network", "offline"] as const) {
      await expect(
        resolveTarget("left-pad@1.3.0", {
          ...scanOptions,
          networkPolicy
        })
      ).rejects.toThrow("Network access is disabled");
    }
  });

  it("rejects npm tarball URLs when network is disabled", async () => {
    for (const networkPolicy of ["no-network", "offline"] as const) {
      await expect(
        resolveTarget("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", {
          ...scanOptions,
          networkPolicy
        })
      ).rejects.toThrow("Network access is disabled");
    }
  });

  it("recognizes npm package specs", async () => {
    const target = await resolveTarget("left-pad@1.3.0", scanOptions);

    expect(target.type).toBe("npm-package");
    expect(target.source).toBe("left-pad@1.3.0");
    expect(target.localPath).toBeNull();
    expect(target.networkUsed).toBe(true);
  });

  it.each([
    "http://example.com/source.zip",
    "https://example.com/source.zip",
    "http://example.com/source.tgz",
    "https://example.com/source.tgz",
    "http://example.com/source.tar.gz",
    "https://example.com/source.tar.gz"
  ])("recognizes remote archive URL %s", async (source) => {
    const target = await resolveTarget(source, scanOptions);

    expect(target.type).toBe("remote-archive");
    expect(target.source).toBe(source);
    expect(target.localPath).toBeNull();
    expect(target.networkUsed).toBe(true);
    expect(target.trustBoundary).toBe("archive");
  });

  it("rejects remote archive URLs when network is disabled", async () => {
    await expect(
      resolveTarget("http://example.com/source.zip", {
        reviewMode: "full-audit",
        networkPolicy: "offline",
        outputFormats: ["json"]
      })
    ).rejects.toThrow("Network access is disabled");
  });

  it("does not use package-root fallback for missing relative paths", async () => {
    const originalCwd = process.cwd();
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "resolver-target-"));

    try {
      process.chdir(tempDir);

      await expect(
        resolveTarget("../../fixtures/benign-package", {
          reviewMode: "full-audit",
          networkPolicy: "offline",
          outputFormats: ["json"]
        })
      ).rejects.toThrow("Unsupported target");
    } finally {
      process.chdir(originalCwd);
      await fs.rm(tempDir, { force: true, recursive: true });
    }
  });
});
