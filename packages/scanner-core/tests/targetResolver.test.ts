import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { resolveTarget } from "../src/targetResolver.js";

describe("resolveTarget", () => {
  it("resolves local directories without network", async () => {
    const target = await resolveTarget("../../fixtures/benign-package", {
      reviewMode: "full-audit",
      networkPolicy: "offline",
      outputFormats: ["json"]
    });

    expect(target.type).toBe("local-directory");
    expect(target.networkUsed).toBe(false);
    expect(target.trustBoundary).toBe("local");
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

  it("recognizes npm package specs", async () => {
    const target = await resolveTarget("left-pad@1.3.0", {
      reviewMode: "full-audit",
      networkPolicy: "online",
      outputFormats: ["json"]
    });

    expect(target.type).toBe("npm-package");
    expect(target.source).toBe("left-pad@1.3.0");
    expect(target.networkUsed).toBe(true);
  });

  it("recognizes http remote archive URLs", async () => {
    const target = await resolveTarget("http://example.com/source.zip", {
      reviewMode: "full-audit",
      networkPolicy: "online",
      outputFormats: ["json"]
    });

    expect(target.type).toBe("remote-archive");
    expect(target.networkUsed).toBe(true);
    expect(target.trustBoundary).toBe("archive");
  });
});
