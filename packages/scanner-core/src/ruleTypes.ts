import type { ProjectInventory } from "./inventory.js";
import type { Finding, FindingCategory, RiskLevel } from "./types.js";
import { matchesGlob } from "./glob.js";

export interface RuleMatchCondition {
  field: string;
  operator: "equals" | "contains" | "matches" | "in" | "not_in";
  value: string | string[];
}

export interface RuleDefinition {
  id: string;
  description: string;
  category: FindingCategory;
  defaultRiskLevel: RiskLevel;
  inventoryField: string;
  pathPattern?: string;
  conditions: RuleMatchCondition[];
  explanation: string;
  recommendedFix: string;
  tags: string[];
}

export type RuleHandler = (
  inventory: ProjectInventory
) => Finding[];

export type CompiledRule = RuleDefinition & {
  match: (item: unknown) => boolean;
};

export function compileRule(rule: RuleDefinition): CompiledRule {
  const pathAllowed = rule.pathPattern
    ? (filePath: string) => matchesGlob(rule.pathPattern as string, filePath)
    : () => true;

  return {
    ...rule,
    match: (item: unknown) => {
      const obj = item as Record<string, unknown>;
      if (!pathAllowed(String(obj.filePath ?? ""))) {
        return false;
      }
      return rule.conditions.every((cond) => {
        const val = String(obj[cond.field] ?? "");
        switch (cond.operator) {
          case "equals":
            return val === cond.value;
          case "contains":
            return val.includes(String(cond.value));
          case "matches":
            return new RegExp(String(cond.value)).test(val);
          case "in":
            return (cond.value as string[]).includes(val);
          case "not_in":
            return !(cond.value as string[]).includes(val);
          default:
            return false;
        }
      });
    }
  };
}
