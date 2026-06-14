import type { ProjectInventory } from "./inventory.js";
import type { DataFlowGraph, Finding } from "./types.js";

export function buildDataFlowGraph(inventory: ProjectInventory, findings: Finding[]): DataFlowGraph {
  const endpoints = Array.from(new Set(inventory.networkEndpoints.map((endpoint) => endpoint.endpoint))).sort();
  const nodes = [
    ...inventory.environmentVariables.map((name) => ({
      id: `env:${name}`,
      label: `env:${name}`,
      kind: "source" as const,
      leavesMachine: false
    })),
    ...endpoints.map((endpoint) => ({
      id: `external:${endpoint}`,
      label: endpoint,
      kind: "external-destination" as const,
      leavesMachine: true
    }))
  ];

  const edges = endpoints.flatMap((endpoint) =>
    inventory.environmentVariables.map((envName) => ({
      id: `edge:${envName}->${endpoint}`,
      from: `env:${envName}`,
      to: `external:${endpoint}`,
      label: "possible outbound flow",
      findingIds: findings.filter((finding) => finding.sink === endpoint).map((finding) => finding.id)
    }))
  );

  return { nodes, edges };
}
