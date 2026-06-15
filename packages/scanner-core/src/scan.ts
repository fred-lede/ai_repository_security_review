import { buildDataFlowGraph } from "./dataFlow.js";
import { buildInventory } from "./inventory.js";
import {
  buildAttackSurface,
  renderDecisionRecord,
  renderHtmlReport,
  renderJsonReport,
  renderMarkdownReport,
  renderMermaidDataFlow,
  renderRemediationList,
  renderSarifReport
} from "./reporters.js";
import { acquireRemoteTarget } from "./remoteAcquisition.js";
import { assessRisk } from "./risk.js";
import { runRules } from "./rules.js";
import { resolveTarget } from "./targetResolver.js";
import type { AuditReport, Language, OutputFormat, ScanOptions } from "./types.js";

export type ScanOutputName = OutputFormat | "decision" | "remediation";

export interface ScanResult {
  report: AuditReport;
  outputs: Partial<Record<ScanOutputName, string>>;
}

export async function scanTarget(input: string, options: ScanOptions): Promise<ScanResult> {
  const target = await resolveTarget(input, options);

  const scanPath = await acquireRemoteTarget(target);

  const inventory = await buildInventory(scanPath);
  const findings = runRules(inventory, options.extraRules);
  const dataFlow = buildDataFlowGraph(inventory, findings);
  const lang = options.language ?? "zh-TW";
  const risk = assessRisk(findings, lang);
  const report: AuditReport = {
    target,
    findings,
    dataFlow,
    risk,
    attackSurface: [],
    generatedAt: new Date().toISOString(),
    toolVersion: "0.1.0"
  };

  report.attackSurface = buildAttackSurface(report);

  return {
    report,
    outputs: renderOutputs(report, options.outputFormats, lang)
  };
}

function renderOutputs(report: AuditReport, outputFormats: OutputFormat[], lang: Language = "zh-TW"): ScanResult["outputs"] {
  const selectedFormats = new Set(outputFormats);
  const outputs: ScanResult["outputs"] = {
    decision: renderDecisionRecord(report, lang),
    remediation: renderRemediationList(report, lang)
  };

  if (selectedFormats.has("markdown")) {
    outputs.markdown = renderMarkdownReport(report, lang);
  }

  if (selectedFormats.has("json")) {
    outputs.json = renderJsonReport(report, lang);
  }

  if (selectedFormats.has("mermaid")) {
    outputs.mermaid = renderMermaidDataFlow(report.dataFlow);
  }

  if (selectedFormats.has("sarif")) {
    outputs.sarif = renderSarifReport(report, lang);
  }

  if (selectedFormats.has("html")) {
    outputs.html = renderHtmlReport(report, lang);
  }

  if (selectedFormats.has("pdf")) {
    outputs.pdf = renderHtmlReport(report, lang);
  }

  return outputs;
}
