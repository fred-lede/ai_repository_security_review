import { buildDataFlowGraph } from "./dataFlow.js";
import { buildInventory } from "./inventory.js";
import {
  renderDecisionRecord,
  renderJsonReport,
  renderMarkdownReport,
  renderMermaidDataFlow,
  renderRemediationList,
  renderSarifReport
} from "./reporters.js";
import { assessRisk } from "./risk.js";
import { runRules } from "./rules.js";
import { resolveTarget } from "./targetResolver.js";
import type { AuditReport, OutputFormat, ScanOptions } from "./types.js";

export type ScanOutputName = OutputFormat | "decision" | "remediation";

export interface ScanResult {
  report: AuditReport;
  outputs: Partial<Record<ScanOutputName, string>>;
}

export async function scanTarget(input: string, options: ScanOptions): Promise<ScanResult> {
  const target = await resolveTarget(input, options);

  if (!target.localPath) {
    throw new Error("Remote acquisition is not implemented yet. Use a local folder, file, or archive path.");
  }

  const inventory = await buildInventory(target.localPath);
  const findings = runRules(inventory);
  const dataFlow = buildDataFlowGraph(inventory, findings);
  const risk = assessRisk(findings);
  const report: AuditReport = {
    target,
    findings,
    dataFlow,
    risk,
    generatedAt: new Date().toISOString(),
    toolVersion: "0.1.0"
  };

  return {
    report,
    outputs: renderOutputs(report, options.outputFormats)
  };
}

function renderOutputs(report: AuditReport, outputFormats: OutputFormat[]): ScanResult["outputs"] {
  const selectedFormats = new Set(outputFormats);
  const outputs: ScanResult["outputs"] = {
    decision: renderDecisionRecord(report),
    remediation: renderRemediationList(report)
  };

  if (selectedFormats.has("markdown")) {
    outputs.markdown = renderMarkdownReport(report);
  }

  if (selectedFormats.has("json")) {
    outputs.json = renderJsonReport(report);
  }

  if (selectedFormats.has("mermaid")) {
    outputs.mermaid = renderMermaidDataFlow(report.dataFlow);
  }

  if (selectedFormats.has("sarif")) {
    outputs.sarif = renderSarifReport(report);
  }

  return outputs;
}
