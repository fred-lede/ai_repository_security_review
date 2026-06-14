import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  assertNoSymlinkArchiveEntry,
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
    expect(() => assertNoSymlinkArchiveEntry("link", "symlink")).toThrow(
      "Archive entry is a symlink"
    );
    expect(assertNoSymlinkArchiveEntry("file.txt", "file")).toBe("file");
    expect(assertNoSymlinkArchiveEntry("directory", "directory")).toBe("directory");
  });
});
