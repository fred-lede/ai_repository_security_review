import path from "node:path";

export type ArchiveEntryType = "file" | "directory" | "symlink";

/**
 * Lexically validates that an archive entry path stays inside outputDir.
 * Call assertNoSymlinkArchiveEntry separately before extraction.
 */
export function assertSafeArchiveEntry(entryName: string, outputDir: string): string {
  if (path.isAbsolute(entryName)) {
    throw new Error(`Archive entry uses an absolute path: ${entryName}`);
  }

  const targetPath = path.resolve(outputDir, entryName);
  const normalizedOutput = path.resolve(outputDir);

  if (!targetPath.startsWith(`${normalizedOutput}${path.sep}`) && targetPath !== normalizedOutput) {
    throw new Error(`Archive entry escapes output directory: ${entryName}`);
  }

  return targetPath;
}

export function assertNoSymlinkArchiveEntry(
  entryName: string,
  entryType: ArchiveEntryType
): ArchiveEntryType {
  if (entryType === "symlink") {
    throw new Error(`Archive entry is a symlink and cannot be safely extracted: ${entryName}`);
  }

  return entryType;
}

export function isSupportedArchive(filePath: string): boolean {
  return filePath.endsWith(".zip") || filePath.endsWith(".tgz") || filePath.endsWith(".tar.gz");
}
