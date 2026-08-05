import fs from "node:fs/promises";
import path from "node:path";
import { listScannableFiles, matchesGlob } from "@repo-auditor/scanner-core";

export type ToolMode = "snippets" | "full-files";

export interface ReviewToolContext {
  scanPath: string;
  mode: ToolMode;
  allowedFiles?: string[];
}

export interface ToolDefinition {
  name: string;
  description: string;
  run: (args: Record<string, unknown>, ctx: ReviewToolContext) => Promise<string>;
}

const MAX_FILE_BYTES = 60 * 1024;
const MAX_FILE_LINES = 2000;
const MAX_SEARCH_RESULTS = 20;
const MAX_FIND_RESULTS = 50;

function resolveWithin(root: string, relPath: string): string {
  const rootAbs = path.resolve(root);
  const resolved = path.resolve(rootAbs, relPath);
  if (resolved !== rootAbs && !resolved.startsWith(rootAbs + path.sep)) {
    throw new Error(`path escapes scan directory: ${relPath}`);
  }
  return resolved;
}

function toRelative(root: string, abs: string): string {
  return path.relative(root, abs).split(path.sep).join("/");
}

async function fileRead(
  args: Record<string, unknown>,
  ctx: ReviewToolContext
): Promise<string> {
  const relPath = String(args.path ?? "");
  if (!relPath) {
    return "tool error: path is required";
  }
  if (ctx.mode === "snippets" && !(ctx.allowedFiles ?? []).includes(relPath)) {
    throw new Error(`file not allowed in snippets mode: ${relPath}`);
  }

  const abs = resolveWithin(ctx.scanPath, relPath);
  const stat = await fs.stat(abs).catch(() => undefined);
  if (!stat?.isFile()) {
    return `tool error: not a file: ${relPath}`;
  }
  if (stat.size > MAX_FILE_BYTES) {
    return `tool error: file too large: ${relPath}`;
  }

  const content = await fs.readFile(abs, "utf8");
  const lines = content.split(/\r?\n/);
  const start = Number(args.lineStart) > 0 ? Math.floor(Number(args.lineStart)) : 1;
  const end = Number(args.lineEnd) >= start ? Math.min(Math.floor(Number(args.lineEnd)), lines.length) : lines.length;
  const slice = lines.slice(start - 1, end).slice(0, MAX_FILE_LINES);
  const numbered = slice.map((text, i) => `${start + i}\t${text}`).join("\n");
  const header = `file ${toRelative(ctx.scanPath, abs)} lines ${start}-${Math.min(end, lines.length)} of ${lines.length}`;
  return `${header}\n${numbered}`;
}

async function fileFind(
  args: Record<string, unknown>,
  ctx: ReviewToolContext
): Promise<string> {
  const pattern = String(args.pattern ?? "");
  if (!pattern) {
    return "tool error: pattern is required";
  }
  const files = await listScannableFiles(ctx.scanPath).catch(() => []);
  const matched = files.filter((file) => matchesGlob(pattern, file)).slice(0, MAX_FIND_RESULTS);
  return matched.length > 0 ? `files:\n${matched.join("\n")}` : "no files matched";
}

async function codeSearch(
  args: Record<string, unknown>,
  ctx: ReviewToolContext
): Promise<string> {
  const query = String(args.query ?? "");
  if (!query) {
    return "tool error: query is required";
  }
  let regex: RegExp;
  try {
    regex = new RegExp(query);
  } catch {
    return `tool error: invalid regex: ${query}`;
  }

  const files = await listScannableFiles(ctx.scanPath).catch(() => []);
  const hits: string[] = [];
  for (const rel of files) {
    if (hits.length >= MAX_SEARCH_RESULTS) {
      break;
    }
    const abs = resolveWithin(ctx.scanPath, rel);
    const stat = await fs.stat(abs).catch(() => undefined);
    if (!stat?.isFile() || stat.size > MAX_FILE_BYTES) {
      continue;
    }
    const content = await fs.readFile(abs, "utf8").catch(() => "");
    for (const [idx, line] of content.split(/\r?\n/).entries()) {
      if (regex.test(line)) {
        hits.push(`${rel}:${idx + 1}\t${line.trim().slice(0, 200)}`);
        if (hits.length >= MAX_SEARCH_RESULTS) {
          break;
        }
      }
    }
  }
  return hits.length > 0 ? `matches (${hits.length} shown):\n${hits.join("\n")}` : "no matches";
}

const fileReadTool: ToolDefinition = {
  name: "file_read",
  description: "Read a file (or a line range) from the scanned project. Args: { path, lineStart?, lineEnd? }",
  run: fileRead
};

const fileFindTool: ToolDefinition = {
  name: "file_find",
  description: "Find files in the project matching a glob pattern. Args: { pattern }",
  run: fileFind
};

const codeSearchTool: ToolDefinition = {
  name: "code_search",
  description: "Regex search across project file contents. Args: { query }",
  run: codeSearch
};

export function buildTools(
  dataSharingMode: "metadata-only" | "finding-snippets" | "full-files",
  ctx: ReviewToolContext
): ToolDefinition[] {
  if (dataSharingMode === "metadata-only") {
    return [];
  }
  const tools: ToolDefinition[] = [fileReadTool];
  if (dataSharingMode === "full-files") {
    tools.push(fileFindTool, codeSearchTool);
  }
  return tools;
}
