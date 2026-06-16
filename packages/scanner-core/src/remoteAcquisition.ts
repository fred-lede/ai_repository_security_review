import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import https from "node:https";
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

function httpsGet(url: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    https.get(url, { timeout: 60_000 }, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return httpsGet(res.headers.location).then(resolve, reject);
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => resolve(Buffer.concat(chunks)));
      res.on("error", reject);
    }).on("error", reject);
  });
}

async function resolveNpmTarballUrl(spec: string): Promise<string> {
  const atIdx = spec.indexOf("@", spec.startsWith("@") ? 1 : 0);
  const pkgName = atIdx > 0 ? spec.slice(0, atIdx) : spec;
  const version = atIdx > 0 ? spec.slice(atIdx + 1) : "latest";
  const encodedName = encodeURIComponent(pkgName);
  const url = `https://registry.npmjs.org/${encodedName}/${version}`;
  const data = await httpsGet(url);
  const meta = JSON.parse(data.toString("utf8"));
  if (!meta?.dist?.tarball) {
    throw new Error(`Could not resolve tarball for ${spec}`);
  }
  return meta.dist.tarball;
}

async function downloadAndExtractTgz(tarballUrl: string, destDir: string): Promise<void> {
  const tgzData = await httpsGet(tarballUrl);
  const tmpFile = path.join(destDir, "package.tgz");
  await fs.writeFile(tmpFile, tgzData);
  try {
    await execFileAsync("tar", ["xzf", tmpFile, "-C", destDir], {
      timeout: 60_000,
      maxBuffer: 1024 * 1024
    });
  } finally {
    await fs.unlink(tmpFile).catch(() => {});
  }
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
    case "npm-package": {
      const dir = cloneDirFor(target.source);
      await fs.rm(dir, { recursive: true, force: true });
      await fs.mkdir(dir, { recursive: true });

      try {
        const tarballUrl = await resolveNpmTarballUrl(target.source);
        await downloadAndExtractTgz(tarballUrl, dir);
        const packageDir = path.join(dir, "package");
        const stat = await fs.stat(packageDir).catch(() => undefined);
        return stat?.isDirectory() ? packageDir : dir;
      } catch (error) {
        await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
        throw new Error(
          `Failed to acquire npm package ${target.source}: ${error instanceof Error ? error.message : "unknown error"}`
        );
      }
    }
    case "npm-tarball":
    case "remote-archive": {
      const dir = cloneDirFor(target.source);
      await fs.rm(dir, { recursive: true, force: true });
      await fs.mkdir(dir, { recursive: true });

      try {
        await downloadAndExtractTgz(target.source, dir);
        const packageDir = path.join(dir, "package");
        const stat = await fs.stat(packageDir).catch(() => undefined);
        return stat?.isDirectory() ? packageDir : dir;
      } catch (error) {
        await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
        throw new Error(
          `Failed to acquire remote archive ${target.source}: ${error instanceof Error ? error.message : "unknown error"}`
        );
      }
    }
    default:
      throw new Error(`Unsupported remote target type: ${target.type}`);
  }
}

export async function cleanupRemoteDir(target: ResolvedTarget): Promise<void> {
  const dir = cloneDirFor(target.source);
  await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
}
