import type { ProjectInventory } from "./inventory.js";
import type { DataFlowGraph, Finding } from "./types.js";

export function buildDataFlowGraph(inventory: ProjectInventory, findings: Finding[]): DataFlowGraph {
  const endpoints = Array.from(new Set(inventory.networkEndpoints.map((endpoint) => endpoint.endpoint))).sort();
  const sourceNodes = [
    ...inventory.environmentVariables.map((name) => ({
      id: `env:${name}`,
      label: `env:${name}`,
      kind: "source" as const,
      leavesMachine: false
    })),
    ...inventory.filesystemReads.map((read) => ({
      id: `fs:${read.filePath}:${read.line}`,
      label: `fs:${read.filePath}:${read.line} ${read.snippet}`,
      kind: "source" as const,
      leavesMachine: false
    }))
  ];
  const nodes = [
    ...sourceNodes,
    ...endpoints.map((endpoint) => ({
      id: `external:${endpoint}`,
      label: endpoint,
      kind: "external-destination" as const,
      leavesMachine: true
    }))
  ];

  const edges = endpoints.flatMap((endpoint) =>
    sourceNodes.map((source) => ({
      id: `edge:${source.id}->${endpoint}`,
      from: source.id,
      to: `external:${endpoint}`,
      label: "possible outbound flow",
      findingIds: findings.filter((finding) => finding.sink === endpoint).map((finding) => finding.id)
    }))
  );

  return { nodes, edges };
}
