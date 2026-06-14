import path from "node:path";

export function assertSafeArchiveEntry(entryName: string, outputDir: string): string {
  const targetPath = path.resolve(outputDir, entryName);
  const normalizedOutput = path.resolve(outputDir);

  if (!targetPath.startsWith(`${normalizedOutput}${path.sep}`) && targetPath !== normalizedOutput) {
    throw new Error(`Archive entry escapes output directory: ${entryName}`);
  }

  if (path.isAbsolute(entryName)) {
    throw new Error(`Archive entry uses an absolute path: ${entryName}`);
  }

  return targetPath;
}

export function isSupportedArchive(filePath: string): boolean {
  return filePath.endsWith(".zip") || filePath.endsWith(".tgz") || filePath.endsWith(".tar.gz");
}
