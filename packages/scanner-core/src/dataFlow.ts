import type { ProjectInventory } from "./inventory.js";
import type { DataFlowEdge, DataFlowGraph, DataFlowNode, Finding } from "./types.js";

export function buildDataFlowGraph(inventory: ProjectInventory, findings: Finding[]): DataFlowGraph {
  const graph = new GraphBuilder();
  const sourceNodes = [
    ...inventory.environmentVariables.map((name) =>
      graph.addNode({
        id: `env:${name}`,
        label: `env:${name}`,
        kind: "source",
        leavesMachine: false
      })
    ),
    ...inventory.filesystemReads.map((read) =>
      graph.addNode({
        id: `fs:${read.filePath}:${read.line}`,
        label: `fs:${read.filePath}:${read.line} ${read.snippet}`,
        kind: "source",
        leavesMachine: false
      })
    )
  ];

  const externalEndpoints = collectExternalEndpoints(inventory, findings);
  const externalNodes = new Map(
    externalEndpoints.map((endpoint) => [
      endpoint,
      graph.addNode({
        id: `external:${endpoint}`,
        label: endpoint,
        kind: "external-destination",
        leavesMachine: true
      })
    ])
  );

  const networkApis = collectNetworkApis(inventory, findings);
  for (const api of networkApis) {
    const apiNode = graph.addNode({
      id: api.id,
      label: `${api.kind}:${api.filePath}:${api.line} ${api.endpoint ?? api.snippet ?? ""}`.trim(),
      kind: "process",
      leavesMachine: false
    });
    connectSourcesToApi(graph, sourceNodes, apiNode, api.findingIds);

    for (const endpoint of api.endpoint ? [api.endpoint] : extractExternalEndpoints(api.snippet ?? "")) {
      const destination = externalNodes.get(endpoint);
      if (destination) {
        graph.addEdge({
          id: `edge:${apiNode.id}->${destination.id}`,
          from: apiNode.id,
          to: destination.id,
          label: "outbound external call",
          findingIds: api.findingIds
        });
      }
    }
  }

  const commandApis = collectCommandApis(inventory, findings);
  for (const api of commandApis) {
    const apiNode = graph.addNode({
      id: api.id,
      label: `${api.kind}:${api.filePath}:${api.line} ${api.snippet ?? ""}`.trim(),
      kind: "process",
      leavesMachine: false
    });
    connectSourcesToApi(graph, sourceNodes, apiNode, api.findingIds);

    for (const endpoint of extractExternalEndpoints(api.snippet ?? "")) {
      const destination = externalNodes.get(endpoint);
      if (destination) {
        graph.addEdge({
          id: `edge:${apiNode.id}->${destination.id}`,
          from: apiNode.id,
          to: destination.id,
          label: "command reaches external endpoint",
          findingIds: api.findingIds
        });
      }
    }
  }

  for (const api of collectLocalApis(inventory, findings)) {
    const apiNode = graph.addNode({
      id: api.id,
      label: `${api.kind}:${api.filePath}:${api.line} ${api.snippet ?? ""}`.trim(),
      kind: "process",
      leavesMachine: false
    });
    connectSourcesToApi(graph, sourceNodes, apiNode, api.findingIds);

    if (api.localDestinationId) {
      const destination = graph.addNode({
        id: api.localDestinationId,
        label: api.localDestinationLabel ?? api.localDestinationId,
        kind: "local-sink",
        leavesMachine: false
      });
      graph.addEdge({
        id: `edge:${apiNode.id}->${destination.id}`,
        from: apiNode.id,
        to: destination.id,
        label: localSinkEdgeLabel(api.kind),
        findingIds: api.findingIds
      });
    }
  }

  for (const endpoint of externalEndpoints) {
    const destination = externalNodes.get(endpoint);
    if (!destination) {
      continue;
    }

    for (const source of sourceNodes) {
      graph.addEdge({
        id: `edge:${source.id}->${endpoint}`,
        from: source.id,
        to: destination.id,
        label: "possible outbound flow",
        findingIds: findings.filter((finding) => finding.sink === endpoint).map((finding) => finding.id)
      });
    }
  }

  return graph.toGraph();
}

interface ApiDescriptor {
  id: string;
  kind:
    | "network api"
    | "command api"
    | "filesystem api"
    | "persistence api"
    | "electron-ipc api"
    | "github-actions api";
  filePath: string;
  line: number;
  snippet?: string;
  endpoint?: string;
  findingIds: string[];
  localDestinationId?: string;
  localDestinationLabel?: string;
}

class GraphBuilder {
  private readonly nodes = new Map<string, DataFlowNode>();
  private readonly edges = new Map<string, DataFlowEdge>();

  addNode(node: DataFlowNode): DataFlowNode {
    const existing = this.nodes.get(node.id);
    if (existing) {
      return existing;
    }

    this.nodes.set(node.id, node);
    return node;
  }

  addEdge(edge: DataFlowEdge): void {
    const existing = this.edges.get(edge.id);
    if (existing) {
      existing.findingIds = Array.from(new Set([...existing.findingIds, ...edge.findingIds])).sort();
      return;
    }

    this.edges.set(edge.id, { ...edge, findingIds: Array.from(new Set(edge.findingIds)).sort() });
  }

  toGraph(): DataFlowGraph {
    return {
      nodes: Array.from(this.nodes.values()),
      edges: Array.from(this.edges.values())
    };
  }
}

function collectExternalEndpoints(inventory: ProjectInventory, findings: Finding[]): string[] {
  return Array.from(
    new Set([
      ...inventory.networkEndpoints.map((endpoint) => endpoint.endpoint),
      ...findings.flatMap((finding) => [
        ...(finding.sink && isExternalEndpoint(finding.sink) ? [finding.sink] : []),
        ...extractExternalEndpoints(finding.codeSnippet)
      ])
    ])
  ).sort();
}

function collectNetworkApis(inventory: ProjectInventory, findings: Finding[]): ApiDescriptor[] {
  const apis = [
    ...inventory.networkEndpoints.map((endpoint) => ({
      id: `network api:${endpoint.filePath}:${endpoint.line}`,
      kind: "network api" as const,
      filePath: endpoint.filePath,
      line: endpoint.line,
      snippet: endpoint.snippet,
      endpoint: endpoint.endpoint,
      findingIds: matchingFindingIds(findings, endpoint.filePath, endpoint.line, (finding) => finding.sink === endpoint.endpoint)
    })),
    ...findings
      .filter((finding) => isNetworkFinding(finding))
      .map((finding) => ({
        id: `network api:${finding.filePath}:${finding.lineStart}`,
        kind: "network api" as const,
        filePath: finding.filePath,
        line: finding.lineStart,
        snippet: finding.codeSnippet,
        endpoint: finding.sink && isExternalEndpoint(finding.sink) ? finding.sink : extractExternalEndpoints(finding.codeSnippet)[0],
        findingIds: [finding.id]
      }))
  ];

  return uniqueApis(apis);
}

function collectCommandApis(inventory: ProjectInventory, findings: Finding[]): ApiDescriptor[] {
  return uniqueApis([
    ...inventory.commandExecutions.map((command) => ({
      id: `command api:${command.filePath}:${command.line}`,
      kind: "command api" as const,
      filePath: command.filePath,
      line: command.line,
      snippet: command.snippet,
      findingIds: matchingFindingIds(findings, command.filePath, command.line, (finding) =>
        finding.evidenceTags.includes("command-execution")
      )
    })),
    ...findings
      .filter((finding) => finding.category === "command-injection" || finding.category === "remote-code-execution")
      .map((finding) => ({
        id: `command api:${finding.filePath}:${finding.lineStart}`,
        kind: "command api" as const,
        filePath: finding.filePath,
        line: finding.lineStart,
        snippet: finding.codeSnippet,
        findingIds: [finding.id]
      }))
  ]);
}

function collectLocalApis(inventory: ProjectInventory, findings: Finding[]): ApiDescriptor[] {
  return uniqueApis([
    ...inventory.persistenceIndicators.map((indicator) => ({
      id: `persistence api:${indicator.filePath}:${indicator.line}`,
      kind: "persistence api" as const,
      filePath: indicator.filePath,
      line: indicator.line,
      snippet: indicator.snippet,
      findingIds: matchingFindingIds(findings, indicator.filePath, indicator.line, (finding) => isPersistenceFinding(finding)),
      localDestinationId: `local:persistence:${indicator.filePath}:${indicator.line}`,
      localDestinationLabel: `local persistence:${indicator.filePath}:${indicator.line}`
    })),
    ...findings
      .filter((finding) => isFilesystemWriteFinding(finding))
      .map((finding) => ({
        id: `filesystem api:${finding.filePath}:${finding.lineStart}`,
        kind: "filesystem api" as const,
        filePath: finding.filePath,
        line: finding.lineStart,
        snippet: finding.codeSnippet,
        findingIds: [finding.id],
        localDestinationId: `local:filesystem:${finding.filePath}:${finding.lineStart}`,
        localDestinationLabel: `local filesystem:${finding.filePath}:${finding.lineStart}`
      })),
    ...findings
      .filter((finding) => isPersistenceFinding(finding))
      .map((finding) => ({
        id: `persistence api:${finding.filePath}:${finding.lineStart}`,
        kind: "persistence api" as const,
        filePath: finding.filePath,
        line: finding.lineStart,
        snippet: finding.codeSnippet,
        findingIds: [finding.id],
        localDestinationId: `local:persistence:${finding.filePath}:${finding.lineStart}`,
        localDestinationLabel: `local persistence:${finding.filePath}:${finding.lineStart}`
      })),
    ...inventory.githubWorkflowFiles.map((filePath) => ({
      id: `github-actions api:${filePath}:1`,
      kind: "github-actions api" as const,
      filePath,
      line: 1,
      snippet: filePath,
      findingIds: matchingFindingIds(findings, filePath, 1, (finding) => finding.category === "github-actions")
    })),
    ...findings
      .filter((finding) => finding.category === "github-actions")
      .map((finding) => ({
        id: `github-actions api:${finding.filePath}:${finding.lineStart}`,
        kind: "github-actions api" as const,
        filePath: finding.filePath,
        line: finding.lineStart,
        snippet: finding.codeSnippet,
        findingIds: [finding.id]
      })),
    ...inventory.electronIpcFiles.map((filePath) => ({
      id: `electron-ipc api:${filePath}:1`,
      kind: "electron-ipc api" as const,
      filePath,
      line: 1,
      snippet: filePath,
      findingIds: matchingFindingIds(findings, filePath, 1, (finding) => finding.category === "electron-ipc")
    })),
    ...findings
      .filter((finding) => finding.category === "electron-ipc")
      .map((finding) => ({
        id: `electron-ipc api:${finding.filePath}:${finding.lineStart}`,
        kind: "electron-ipc api" as const,
        filePath: finding.filePath,
        line: finding.lineStart,
        snippet: finding.codeSnippet,
        findingIds: [finding.id]
      }))
  ]);
}

function connectSourcesToApi(
  graph: GraphBuilder,
  sourceNodes: DataFlowNode[],
  apiNode: DataFlowNode,
  findingIds: string[]
): void {
  for (const source of sourceNodes) {
    graph.addEdge({
      id: `edge:${source.id}->${apiNode.id}`,
      from: source.id,
      to: apiNode.id,
      label: "possible sensitive input",
      findingIds
    });
  }
}

function matchingFindingIds(
  findings: Finding[],
  filePath: string,
  line: number,
  predicate: (finding: Finding) => boolean
): string[] {
  return findings
    .filter(
      (finding) =>
        finding.filePath === filePath &&
        finding.lineStart <= line &&
        finding.lineEnd >= line &&
        predicate(finding)
    )
    .map((finding) => finding.id);
}

function uniqueApis(apis: ApiDescriptor[]): ApiDescriptor[] {
  const byId = new Map<string, ApiDescriptor>();

  for (const api of apis) {
    const existing = byId.get(api.id);
    if (!existing) {
      byId.set(api.id, { ...api, findingIds: Array.from(new Set(api.findingIds)).sort() });
      continue;
    }

    existing.findingIds = Array.from(new Set([...existing.findingIds, ...api.findingIds])).sort();
    existing.endpoint ??= api.endpoint;
    existing.snippet ??= api.snippet;
    existing.localDestinationId ??= api.localDestinationId;
    existing.localDestinationLabel ??= api.localDestinationLabel;
  }

  return Array.from(byId.values()).sort((a, b) => a.id.localeCompare(b.id));
}

function isNetworkFinding(finding: Finding): boolean {
  return (
    finding.category === "network" ||
    finding.category === "data-exfiltration" ||
    finding.category === "credential-leakage" ||
    finding.category === "hidden-telemetry" ||
    finding.category === "tracking" ||
    finding.evidenceTags.includes("network-endpoint") ||
    Boolean(finding.sink && isExternalEndpoint(finding.sink))
  );
}

function isPersistenceFinding(finding: Finding): boolean {
  const evidence = `${finding.category} ${finding.codeSnippet} ${finding.evidenceTags.join(" ")}`.toLowerCase();
  return (
    finding.category === "persistence" ||
    finding.category === "database" ||
    /\b(sqlite|postgres|mysql|mongodb|redis|database|prisma)\b/.test(evidence)
  );
}

function isFilesystemWriteFinding(finding: Finding): boolean {
  const evidence = `${finding.category} ${finding.codeSnippet} ${finding.evidenceTags.join(" ")}`.toLowerCase();
  return (
    finding.category === "filesystem" &&
    /\b(writefilesync|writefile|appendfilesync|appendfile|createwritestream|mkdir|rm|unlink|rename|filesystem-write)\b/.test(
      evidence
    )
  );
}

function localSinkEdgeLabel(kind: ApiDescriptor["kind"]): string {
  return kind === "filesystem api" ? "local filesystem sink" : "local persistence sink";
}

function extractExternalEndpoints(value: string): string[] {
  return Array.from(new Set(Array.from(value.matchAll(/https?:\/\/[^\s"'`)]+/g), (match) => match[0]))).sort();
}

function isExternalEndpoint(value: string): boolean {
  return /^https?:\/\//.test(value);
}
