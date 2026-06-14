import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import type { ResolvedTarget } from "./types.js";

const execFileAsync = promisify(execFile);

function sanitizeDirName(input: string): string {
  return input.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 64);
}

function cloneDirFor(source: string): string {
  return path.join(os.tmpdir(), "repo-auditor", sanitizeDirName(source));
}

export async function acquireRemoteTarget(target: ResolvedTarget): Promise<string> {
  if (target.localPath) {
    return target.localPath;
  }

  switch (target.type) {
    case "github": {
      const dir = cloneDirFor(target.source);
      await fs.rm(dir, { recursive: true, force: true });
      await fs.mkdir(path.dirname(dir), { recursive: true });

      try {
        await execFileAsync("git", ["clone", "--depth", "1", target.source, dir], {
          timeout: 120_000,
          maxBuffer: 1024 * 1024
        });
      } catch (error) {
        await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
        throw new Error(
          `Failed to clone ${target.source}: ${error instanceof Error ? error.message : "unknown error"}`
        );
      }

      return dir;
    }
    case "npm-package":
      throw new Error("npm package acquisition is not implemented yet. Download the package manually and scan it locally.");
    case "npm-tarball":
    case "remote-archive":
      throw new Error("Remote archive acquisition is not implemented yet. Download the file and scan it locally.");
    default:
      throw new Error(`Unsupported remote target type: ${target.type}`);
  }
}

export async function cleanupRemoteDir(target: ResolvedTarget): Promise<void> {
  const dir = cloneDirFor(target.source);
  await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
}
