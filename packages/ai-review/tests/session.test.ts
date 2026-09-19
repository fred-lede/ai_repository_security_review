import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { Finding } from "@repo-auditor/scanner-core";
import type { AiProviderConfig } from "../src/types.js";
import {
  findResumableSession,
  listSessions,
  loadSession,
  newSession,
  saveSession,
  sessionFingerprint
} from "../src/session.js";

const config: AiProviderConfig = {
  type: "cloud",
  baseUrl: "https://api.example.test/v1",
  model: "gpt-test",
  apiKey: "secret-key",
  dataSharingMode: "metadata-only",
  redactionEnabled: true,
  timeoutMs: 30000,
  retryLimit: 0
};

const findings: Finding[] = [
  {
    id: "finding-1",
    riskLevel: "High",
    category: "network",
    filePath: "src/index.ts",
    lineStart: 1,
    lineEnd: 1,
    codeSnippet: "fetch('https://evil.example')",
    explanation: "network exfiltration candidate",
    recommendedFix: "Remove sensitive payloads from outbound requests.",
    evidenceTags: ["network-endpoint"],
    confidence: "High"
  },
  {
    id: "finding-2",
    riskLevel: "Medium",
    category: "network",
    filePath: "src/config.ts",
    lineStart: 5,
    lineEnd: 5,
    codeSnippet: "const key = 'abc'",
    explanation: "hardcoded secret",
    recommendedFix: "Move to env vars.",
    evidenceTags: [],
    confidence: "Medium"
  }
];

async function writeWithUpdatedAt(dir: string, session: ReturnType<typeof newSession>, updatedAt: string): Promise<void> {
  await saveSession(dir, session);
  const file = path.join(dir, `${session.id}.json`);
  const data = JSON.parse(await fs.readFile(file, "utf8"));
  data.updatedAt = updatedAt;
  data.status = session.status;
  await fs.writeFile(file, JSON.stringify(data, null, 2));
}

async function tmpDir(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), "session-test-"));
}

describe("session store", () => {
  it("fingerprint is stable for same inputs and changes when model changes", () => {
    const a = sessionFingerprint(config, findings);
    const b = sessionFingerprint(config, [...findings].reverse());
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{16}$/);

    const otherModel = sessionFingerprint({ ...config, model: "different" }, findings);
    expect(otherModel).not.toBe(a);
  });

  it("save → load round-trips batches, status, fingerprint", async () => {
    const dir = await tmpDir();
    const session = newSession(sessionFingerprint(config, findings), "/scan", findings);
    session.batches.push({
      index: 0,
      summary: "batch 0 summary",
      notes: [{ findingId: "finding-1", explanation: "why" }],
      newFindings: []
    });
    await saveSession(dir, session);

    const loaded = await loadSession(dir, session.id);
    expect(loaded?.fingerprint).toBe(session.fingerprint);
    expect(loaded?.status).toBe("running");
    expect(loaded?.batches).toHaveLength(1);
    expect(loaded?.batches[0].notes[0].findingId).toBe("finding-1");
    expect(loaded?.findingIds).toEqual(["finding-1", "finding-2"]);
  });

  it("saveSession creates a missing directory recursively", async () => {
    const base = await tmpDir();
    const dir = path.join(base, "a", "b", "sessions");
    const session = newSession(sessionFingerprint(config, findings), "/scan", findings);
    await saveSession(dir, session);
    const stat = await fs.stat(path.join(dir, `${session.id}.json`));
    expect(stat.isFile()).toBe(true);
  });

  it("findResumableSession returns newest matching non-done session", async () => {
    const dir = await tmpDir();
    const fp = sessionFingerprint(config, findings);

    const done = newSession(fp, "/scan", findings);
    done.id = "done-0001";
    done.status = "done";
    await writeWithUpdatedAt(dir, done, "2026-09-19T00:00:03.000Z");

    const older = newSession(fp, "/scan", findings);
    older.id = "older-0001";
    await writeWithUpdatedAt(dir, older, "2026-09-19T00:00:01.000Z");

    const newer = newSession(fp, "/scan", findings);
    newer.id = "newer-0001";
    await writeWithUpdatedAt(dir, newer, "2026-09-19T00:00:02.000Z");

    const otherFp = newSession("deadbeefdeadbeef", "/scan", findings);
    otherFp.id = "other-0001";
    await writeWithUpdatedAt(dir, otherFp, "2026-09-19T00:00:04.000Z");

    const found = await findResumableSession(dir, fp);
    expect(found?.id).toBe(newer.id);
  });

  it("listSessions returns newest first and skips corrupt files", async () => {
    const dir = await tmpDir();
    const one = newSession(sessionFingerprint(config, findings), "/scan", findings);
    one.id = "one-0001";
    one.batches.push({ index: 0, summary: "s", notes: [], newFindings: [] });
    await writeWithUpdatedAt(dir, one, "2026-09-19T00:00:01.000Z");

    const two = newSession(sessionFingerprint(config, findings), "/scan", findings);
    two.id = "two-0001";
    await writeWithUpdatedAt(dir, two, "2026-09-19T00:00:02.000Z");

    await fs.writeFile(path.join(dir, "corrupt.json"), "not json {{{");

    const list = await listSessions(dir);
    expect(list).toHaveLength(2);
    expect(list[0].id).toBe(two.id);
    expect(list[1].id).toBe(one.id);
    expect(list[1].batchesDone).toBe(1);
    expect(list[1].findingCount).toBe(2);
  });

  it("saveSession does not throw for an unwritable path", async () => {
    const session = newSession(sessionFingerprint(config, findings), "/scan", findings);
    await expect(saveSession("/dev/null/impossible", session)).resolves.toBeUndefined();
  });

  it("loadSession rejects path-traversal-ish ids", async () => {
    const dir = await tmpDir();
    expect(await loadSession(dir, "../evil")).toBeUndefined();
  });
});
