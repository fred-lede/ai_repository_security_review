import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildDataFlowGraph } from "../src/dataFlow.js";
import { buildInventory } from "../src/inventory.js";
import { renderMarkdownReport, renderMermaidDataFlow } from "../src/reporters.js";
import { assessRisk } from "../src/risk.js";
import { runRules } from "../src/rules.js";

describe("reporters", () => {
  it("renders risk, findings, recommendations, and outbound data flow", async () => {
    const root = path.resolve("fixtures/malicious-package");
    const inventory = await buildInventory(root);
    const findings = runRules(inventory);
    const dataFlow = buildDataFlowGraph(inventory, findings);
    const risk = assessRisk(findings);

    const markdown = renderMarkdownReport({
      target: {
        type: "local-directory",
        source: root,
        localPath: root,
        provenance: { source: root },
        networkUsed: false,
        trustBoundary: "local"
      },
      findings,
      dataFlow,
      risk,
      generatedAt: "2026-06-14T00:00:00.000Z",
      toolVersion: "0.1.0"
    });

    expect(risk.decision).toBe("Block");
    expect(markdown).toContain("Executive Summary");
    expect(markdown).toContain("Recommended Fix");
    expect(renderMermaidDataFlow(dataFlow)).toContain("evil.example");
  });
});
