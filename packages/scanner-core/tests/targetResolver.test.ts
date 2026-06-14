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
});
