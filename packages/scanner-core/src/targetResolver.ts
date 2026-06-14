import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { isSupportedArchive } from "./safeArchive.js";
import type { ResolvedTarget, ScanOptions } from "./types.js";

const GITHUB_RE = /^https:\/\/github\.com\/[^/\s]+\/[^/\s]+(?:\.git)?$/;
const HTTP_ARCHIVE_RE = /^https?:\/\/.+\.(?:zip|tgz|tar\.gz)$/;
const NPM_TARBALL_RE = /^https:\/\/registry\.npmjs\.org\/.+\.tgz$/;
const NPM_SPEC_RE = /^(?:@[^/\s]+\/)?[^@\s/]+(?:@[\w.-]+)?$/;

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export async function resolveTarget(input: string, options: ScanOptions): Promise<ResolvedTarget> {
  const localTarget = await resolveLocalTarget(input);

  if (localTarget?.stat.isDirectory()) {
    return {
      type: "local-directory",
      source: input,
      localPath: localTarget.absolutePath,
      provenance: { source: input },
      networkUsed: false,
      trustBoundary: "local"
    };
  }

  if (localTarget?.stat.isFile()) {
    const archive = isSupportedArchive(localTarget.absolutePath);

    return {
      type: archive ? "archive" : "local-file",
      source: input,
      localPath: localTarget.absolutePath,
      provenance: { source: input },
      networkUsed: false,
      trustBoundary: archive ? "archive" : "local"
    };
  }

  if (isRemoteTarget(input) && options.networkPolicy !== "online") {
    throw new Error("Network access is disabled for this target");
  }

  if (GITHUB_RE.test(input)) {
    return remote("github", input);
  }

  if (NPM_TARBALL_RE.test(input)) {
    return remote("npm-tarball", input);
  }

  if (HTTP_ARCHIVE_RE.test(input)) {
    return remote("remote-archive", input);
  }

  if (NPM_SPEC_RE.test(input)) {
    return remote("npm-package", input);
  }

  throw new Error(`Unsupported target: ${input}`);
}

function remote(type: ResolvedTarget["type"], source: string): ResolvedTarget {
  return {
    type,
    source,
    localPath: "",
    provenance: { source },
    networkUsed: true,
    trustBoundary: type === "github" || type === "npm-package" ? "remote" : "archive"
  };
}

function isRemoteTarget(input: string): boolean {
  return input.startsWith("http://") || input.startsWith("https://") || NPM_SPEC_RE.test(input);
}

async function resolveLocalTarget(
  input: string
): Promise<{ absolutePath: string; stat: Awaited<ReturnType<typeof fs.stat>> } | undefined> {
  for (const absolutePath of localPathCandidates(input)) {
    const stat = await fs.stat(absolutePath).catch(() => undefined);

    if (stat) {
      return { absolutePath, stat };
    }
  }

  return undefined;
}

function localPathCandidates(input: string): string[] {
  const candidates = [path.resolve(input)];

  if (!path.isAbsolute(input)) {
    candidates.push(path.resolve(packageRoot, input));
  }

  return [...new Set(candidates)];
}
