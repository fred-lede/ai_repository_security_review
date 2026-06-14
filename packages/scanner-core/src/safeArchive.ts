import path from "node:path";

export type ArchiveEntryType =
  | "file"
  | "directory"
  | "symlink"
  | "hardlink"
  | "block-device"
  | "character-device"
  | "fifo"
  | "unknown";

/**
 * Lexically validates that an archive entry path stays inside outputDir.
 * Call assertRegularArchiveEntry separately before extraction.
 */
export function assertSafeArchiveEntry(entryName: string, outputDir: string): string {
  if (entryName.includes("\0")) {
    throw new Error(`Archive entry contains a NUL byte: ${entryName}`);
  }

  if (path.posix.isAbsolute(entryName) || path.win32.isAbsolute(entryName)) {
    throw new Error(`Archive entry uses an absolute path: ${entryName}`);
  }

  if (entryName.includes("\\")) {
    throw new Error(`Archive entry contains backslashes: ${entryName}`);
  }

  const normalizedEntry = path.posix.normalize(entryName);
  const targetPath = path.resolve(outputDir, ...normalizedEntry.split("/"));
  const normalizedOutput = path.resolve(outputDir);

  if (!targetPath.startsWith(`${normalizedOutput}${path.sep}`) && targetPath !== normalizedOutput) {
    throw new Error(`Archive entry escapes output directory: ${entryName}`);
  }

  return targetPath;
}

export function assertRegularArchiveEntry(
  entryName: string,
  entryType: ArchiveEntryType
): ArchiveEntryType {
  if (entryType !== "file" && entryType !== "directory") {
    throw new Error(
      `Archive entry type is not supported for extraction: ${entryName} (${entryType})`
    );
  }

  return entryType;
}

export const assertNoSymlinkArchiveEntry = assertRegularArchiveEntry;

export function isSupportedArchive(filePath: string): boolean {
  return filePath.endsWith(".zip") || filePath.endsWith(".tgz") || filePath.endsWith(".tar.gz");
}
