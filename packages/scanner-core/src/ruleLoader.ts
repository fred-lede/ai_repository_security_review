import type { RuleDefinition } from "./ruleTypes.js";

const RULES_FILENAME = "repo-auditor-rules.json";

export async function loadExternalRules(
  userDataPath?: string
): Promise<RuleDefinition[]> {
  const fs = await import("node:fs/promises");
  const path = await import("node:path");
  const p = userDataPath
    ? path.join(userDataPath, RULES_FILENAME)
    : RULES_FILENAME;
  try {
    const raw = await fs.readFile(p, "utf-8");
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed as RuleDefinition[];
  } catch {
    return [];
  }
}

export async function saveExternalRules(
  rules: RuleDefinition[],
  userDataPath?: string
): Promise<void> {
  const fs = await import("node:fs/promises");
  const path = await import("node:path");
  const p = userDataPath
    ? path.join(userDataPath, RULES_FILENAME)
    : RULES_FILENAME;
  await fs.writeFile(p, JSON.stringify(rules, null, 2), "utf-8");
}
