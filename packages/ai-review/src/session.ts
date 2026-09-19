import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import type { Finding } from "@repo-auditor/scanner-core";
import type { AgentNote } from "./agent.js";
import type { AiNewFinding, AiProviderConfig } from "./types.js";

export interface SessionBatch {
  index: number;
  summary: string;
  notes: AgentNote[];
  newFindings: AiNewFinding[];
}

export interface AiReviewSession {
  id: string;
  fingerprint: string;
  createdAt: string;
  updatedAt: string;
  status: "running" | "done" | "interrupted";
  scanPath: string;
  findingIds: string[];
  batches: SessionBatch[];
}

export interface SessionListEntry {
  id: string;
  createdAt: string;
  updatedAt: string;
  status: AiReviewSession["status"];
  scanPath: string;
  findingCount: number;
  batchesDone: number;
}

const ID_PATTERN = /^[A-Za-z0-9_.-]+$/;

export function sessionFingerprint(provider: AiProviderConfig, findings: Finding[]): string {
  const payload = {
    type: provider.type,
    baseUrl: provider.baseUrl,
    model: provider.model,
    language: provider.language ?? "zh-TW",
    dataSharingMode: provider.dataSharingMode,
    redactionEnabled: provider.redactionEnabled,
    ids: findings.map((f) => f.id).sort()
  };
  return createHash("sha256").update(JSON.stringify(payload)).digest("hex").slice(0, 16);
}

export function newSession(fingerprint: string, scanPath: string, findings: Finding[]): AiReviewSession {
  const now = new Date().toISOString();
  return {
    id: `${Date.now()}-${fingerprint}`,
    fingerprint,
    createdAt: now,
    updatedAt: now,
    status: "running",
    scanPath,
    findingIds: findings.map((f) => f.id),
    batches: []
  };
}

export async function saveSession(dir: string, session: AiReviewSession): Promise<void> {
  try {
    await fs.mkdir(dir, { recursive: true });
    session.updatedAt = new Date().toISOString();
    const target = path.join(dir, `${session.id}.json`);
    const tmp = path.join(dir, `.${session.id}.tmp`);
    await fs.writeFile(tmp, JSON.stringify(session, null, 2));
    await fs.rename(tmp, target);
  } catch {
    // best-effort: session loss must never fail a review
  }
}

function isValidSession(value: unknown): value is AiReviewSession {
  if (!value || typeof value !== "object") return false;
  const s = value as Record<string, unknown>;
  return (
    typeof s.id === "string" &&
    ID_PATTERN.test(s.id) &&
    typeof s.fingerprint === "string" &&
    typeof s.updatedAt === "string" &&
    Array.isArray(s.batches)
  );
}

export async function loadSession(dir: string, id: string): Promise<AiReviewSession | undefined> {
  if (!ID_PATTERN.test(id)) return undefined;
  try {
    const raw = await fs.readFile(path.join(dir, `${path.basename(id)}.json`), "utf8");
    const parsed: unknown = JSON.parse(raw);
    return isValidSession(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

export async function findResumableSession(
  dir: string,
  fingerprint: string
): Promise<AiReviewSession | undefined> {
  const sessions = await loadAllSessions(dir);
  return sessions
    .filter((s) => s.status !== "done" && s.fingerprint === fingerprint)
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))[0];
}

export async function listSessions(dir: string): Promise<SessionListEntry[]> {
  const sessions = await loadAllSessions(dir);
  return sessions
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
    .map((s) => ({
      id: s.id,
      createdAt: s.createdAt,
      updatedAt: s.updatedAt,
      status: s.status,
      scanPath: s.scanPath,
      findingCount: s.findingIds.length,
      batchesDone: s.batches.length
    }));
}

async function loadAllSessions(dir: string): Promise<AiReviewSession[]> {
  try {
    const entries = await fs.readdir(dir);
    const sessions: AiReviewSession[] = [];
    for (const entry of entries) {
      if (!entry.endsWith(".json")) continue;
      const id = entry.slice(0, -".json".length);
      const session = await loadSession(dir, id);
      if (session) sessions.push(session);
    }
    return sessions;
  } catch {
    return [];
  }
}
