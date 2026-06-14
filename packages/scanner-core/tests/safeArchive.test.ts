import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  assertRegularArchiveEntry,
  assertSafeArchiveEntry,
  isSupportedArchive
} from "../src/safeArchive.js";

describe("safe archive helpers", () => {
  it("allows safe nested paths", () => {
    const outputDir = path.resolve("/tmp/out");

    expect(assertSafeArchiveEntry("nested/file.txt", outputDir)).toBe(
      path.join(outputDir, "nested/file.txt")
    );
  });

  it("allows safe nested POSIX paths", () => {
    const outputDir = path.resolve("/tmp/out");

    expect(assertSafeArchiveEntry("nested/deeper/file.txt", outputDir)).toBe(
      path.join(outputDir, "nested/deeper/file.txt")
    );
  });

  it("rejects parent directory escapes", () => {
    expect(() => assertSafeArchiveEntry("../escape", "/tmp/out")).toThrow(
      "Archive entry escapes output directory"
    );
  });

  it("rejects absolute POSIX paths", () => {
    expect(() => assertSafeArchiveEntry("/tmp/escape", "/tmp/out")).toThrow(
      "Archive entry uses an absolute path"
    );
  });

  it("rejects Windows absolute paths", () => {
    expect(() => assertSafeArchiveEntry("C:\\temp\\x", "/tmp/out")).toThrow(
      "Archive entry uses an absolute path"
    );
  });

  it("rejects UNC paths", () => {
    expect(() => assertSafeArchiveEntry("\\\\server\\share\\x", "/tmp/out")).toThrow(
      "Archive entry uses an absolute path"
    );
  });

  it("rejects backslash traversal paths", () => {
    expect(() => assertSafeArchiveEntry("..\\escape", "/tmp/out")).toThrow(
      "Archive entry contains backslashes"
    );
  });

  it("rejects mixed separator traversal paths", () => {
    expect(() => assertSafeArchiveEntry("safe\\..\\escape", "/tmp/out")).toThrow(
      "Archive entry contains backslashes"
    );
  });

  it("rejects NUL bytes", () => {
    expect(() => assertSafeArchiveEntry("safe\0file", "/tmp/out")).toThrow(
      "Archive entry contains a NUL byte"
    );
  });

  it("rejects prefix sibling escapes", () => {
    expect(() => assertSafeArchiveEntry("../outside/file", "/tmp/out")).toThrow(
      "Archive entry escapes output directory"
    );
  });

  it("recognizes supported archive suffixes", () => {
    expect(isSupportedArchive("source.zip")).toBe(true);
    expect(isSupportedArchive("source.tgz")).toBe(true);
    expect(isSupportedArchive("source.tar.gz")).toBe(true);
    expect(isSupportedArchive("source.tar")).toBe(false);
  });

  it("rejects symlink archive entries", () => {
    expect(() => assertRegularArchiveEntry("link", "symlink")).toThrow(
      "Archive entry type is not supported"
    );
    expect(assertRegularArchiveEntry("file.txt", "file")).toBe("file");
    expect(assertRegularArchiveEntry("directory", "directory")).toBe("directory");
  });

  it("rejects non-regular archive entry types", () => {
    for (const entryType of [
      "hardlink",
      "block-device",
      "character-device",
      "fifo",
      "unknown"
    ] as const) {
      expect(() => assertRegularArchiveEntry("entry", entryType)).toThrow(
        "Archive entry type is not supported"
      );
    }
  });
});
