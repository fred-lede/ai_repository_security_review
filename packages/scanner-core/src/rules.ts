import type { ProjectInventory } from "./inventory.js";
import type { Finding } from "./types.js";
import { applyBuiltinRules } from "./defaultRules.js";
import { compileRule, type RuleDefinition } from "./ruleTypes.js";

export { compileRule };

export function runRules(
  inventory: ProjectInventory,
  extraRules?: RuleDefinition[]
): Finding[] {
  const findings = applyBuiltinRules(inventory);

  if (extraRules && extraRules.length > 0) {
    const compiled = extraRules.map(compileRule);
    const dataIndex = indexInventory(inventory);

    for (const rule of compiled) {
      const items = dataIndex[rule.inventoryField] ?? [];
      for (const item of items) {
        if (rule.match(item)) {
          findings.push({
            id: "",
            category: rule.category,
            riskLevel: rule.defaultRiskLevel,
            filePath: String((item as Record<string, unknown>).filePath ?? ""),
            lineStart: Number((item as Record<string, unknown>).line ?? 1),
            lineEnd: Number((item as Record<string, unknown>).line ?? 1),
            codeSnippet: String((item as Record<string, unknown>).snippet ?? ""),
            explanation: rule.explanation,
            recommendedFix: rule.recommendedFix,
            evidenceTags: [...rule.tags],
            confidence: rule.defaultRiskLevel === "Info" ? "Medium" : "High"
          });
        }
      }
    }
  }

  return findings.map((item, index) => ({ ...item, id: `finding-${index + 1}` }));
}

function indexInventory(inventory: ProjectInventory): Record<string, unknown[]> {
  return {
    packageScripts: inventory.packageScripts as unknown[],
    dependencySources: inventory.dependencySources as unknown[],
    commandExecutions: inventory.commandExecutions as unknown[],
    networkEndpoints: inventory.networkEndpoints as unknown[],
    filesystemReads: inventory.filesystemReads as unknown[],
    files: inventory.files as unknown[]
  };
}
