import type { ProjectInventory } from "./inventory.js";
import type { Finding, RiskLevel } from "./types.js";

export function runRules(inventory: ProjectInventory): Finding[] {
  const findings: Finding[] = [];

  for (const script of inventory.packageScripts) {
    if (["preinstall", "install", "postinstall", "prepare", "prepack", "postpack"].includes(script.name)) {
      findings.push(
        finding({
          category: "postinstall-script",
          riskLevel: "High",
          filePath: script.filePath,
          snippet: `"${script.name}": "${script.command}"`,
          explanation: `The package defines a ${script.name} lifecycle script. Lifecycle scripts run during installation and can execute code before review.`,
          fix: "Remove install-time side effects or move setup behind an explicit user command.",
          tags: ["package-script", script.name]
        })
      );
    }
  }

  for (const dependency of inventory.dependencySources) {
    findings.push(
      finding({
        category: "supply-chain",
        riskLevel: dependency.source.startsWith("file:") ? "Medium" : "High",
        filePath: dependency.filePath,
        snippet: dependency.source,
        explanation: "Dependency source uses git, HTTP, tarball, or local file resolution rather than a pinned registry version.",
        fix: "Replace with a pinned registry version and verify the lockfile integrity.",
        tags: ["dependency-source"]
      })
    );
  }

  for (const command of inventory.commandExecutions) {
    findings.push(
      finding({
        category: "command-injection",
        riskLevel: command.snippet.includes("| bash") ? "Critical" : "High",
        filePath: command.filePath,
        lineStart: command.line,
        lineEnd: command.line,
        snippet: command.snippet,
        explanation:
          "The code invokes shell or process execution. If user-controlled data reaches this call, it can become command injection or RCE.",
        fix: "Avoid shell execution. Use safe APIs with explicit argument arrays and strict input validation.",
        tags: ["command-execution"]
      })
    );
  }

  for (const endpoint of inventory.networkEndpoints) {
    const hasSensitiveSource = inventory.environmentVariables.length > 0 || inventory.filesystemReads.length > 0;
    findings.push(
      finding({
        category: "network",
        riskLevel: hasSensitiveSource ? "High" : "Medium",
        filePath: endpoint.filePath,
        lineStart: endpoint.line,
        lineEnd: endpoint.line,
        snippet: endpoint.snippet,
        explanation: hasSensitiveSource
          ? "The project contains outbound network communication and sensitive local sources, making this an exfiltration candidate. Review whether sensitive data can flow to this destination."
          : "The project communicates with an external endpoint. Confirm this behavior is expected.",
        fix: "Document expected endpoints, minimize payloads, and require explicit consent before sending sensitive data.",
        tags: hasSensitiveSource
          ? ["network-endpoint", "exfiltration-candidate", "sensitive-source-present"]
          : ["network-endpoint"],
        sink: endpoint.endpoint
      })
    );
  }

  return findings.map((item, index) => ({ ...item, id: `finding-${index + 1}` }));
}

function finding(input: {
  category: Finding["category"];
  riskLevel: RiskLevel;
  filePath: string;
  lineStart?: number;
  lineEnd?: number;
  snippet: string;
  explanation: string;
  fix: string;
  tags: string[];
  sink?: string;
}): Finding {
  return {
    id: "",
    riskLevel: input.riskLevel,
    category: input.category,
    filePath: input.filePath,
    lineStart: input.lineStart ?? 1,
    lineEnd: input.lineEnd ?? input.lineStart ?? 1,
    codeSnippet: input.snippet,
    explanation: input.explanation,
    recommendedFix: input.fix,
    evidenceTags: input.tags,
    sink: input.sink,
    confidence: input.riskLevel === "Info" ? "Medium" : "High"
  };
}
