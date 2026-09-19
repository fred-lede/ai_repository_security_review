import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

const actionPath = path.join(__dirname, "../../../action.yml");
const action = parse(fs.readFileSync(actionPath, "utf8")) as {
  name: string;
  description: string;
  inputs: Record<string, { description: string; default?: string }>;
  outputs: Record<string, { description: string; value?: string }>;
  runs: {
    using: string;
    steps: Array<Record<string, unknown>>;
  };
};

const stepIds = () => action.runs.steps.map((step) => String(step.id ?? ""));

describe("composite action", () => {
  it("is a composite action with name and description", () => {
    expect(action.runs.using).toBe("composite");
    expect(action.name).toBe("Repository Security Auditor");
    expect(action.description).toContain("deterministic static analysis");
  });

  it("exposes the intended inputs with defaults", () => {
    expect(Object.keys(action.inputs)).toEqual(["target", "formats", "network-policy", "fail-on-block", "pr-comment"]);
    expect(action.inputs.target.default).toBe(".");
    expect(action.inputs.formats.default).toBe("markdown,json,sarif");
    expect(action.inputs["network-policy"].default).toBe("offline");
    expect(action.inputs["fail-on-block"].default).toBe("true");
    expect(action.inputs["pr-comment"].default).toBe("false");
  });

  it("exposes decision and report-path outputs", () => {
    expect(Object.keys(action.outputs)).toEqual(["decision", "report-path"]);
    expect(action.outputs.decision.value).toContain("steps.scan.outputs.decision");
    expect(action.outputs["report-path"].value).toContain("steps.scan.outputs.report-path");
  });

  it("checks out its own repository before building", () => {
    const checkout = action.runs.steps.find((step) => step.uses === "actions/checkout@v4");
    expect(checkout).toBeDefined();
    const withConfig = checkout?.with as Record<string, string> | undefined;
    expect(withConfig?.repository).toContain("github.action_repository");
    expect(withConfig?.ref).toContain("github.action_ref");
  });

  it("installs dependencies without scripts and builds scanner-core and cli", () => {
    const build = action.runs.steps.find((step) => step.id === undefined && String(step.run ?? "").includes("npm ci --ignore-scripts"));
    expect(build).toBeDefined();
    const run = String(build?.run ?? "");
    expect(run).toContain("@repo-auditor/scanner-core");
    expect(run).toContain("@repo-auditor/cli");
  });

  it("runs the CLI scan and reports decision, report path, and step summary", () => {
    const scan = action.runs.steps.find((step) => step.id === "scan");
    expect(scan).toBeDefined();
    const run = String(scan?.run ?? "");
    expect(run).toContain("packages/cli/dist/index.js scan");
    expect(run).toContain("decision-record.json");
    expect(run).toContain("GITHUB_OUTPUT");
    expect(run).toContain("GITHUB_STEP_SUMMARY");
  });

  it("gates the job on Block only when fail-on-block is enabled", () => {
    const gate = action.runs.steps.find((step) => String(step.name ?? "") === "Fail on Block");
    expect(gate).toBeDefined();
    expect(gate?.if).toContain("inputs.fail-on-block == 'true'");
    expect(String(gate?.run ?? "")).toContain('"Block"');
  });

  it("guards the PR comment step behind pr-comment", () => {
    const comment = action.runs.steps.find((step) => step.uses === "actions/github-script@v7");
    expect(comment).toBeDefined();
    expect(comment?.if).toContain("inputs.pr-comment == 'true'");
    const script = String((comment?.with as Record<string, string> | undefined)?.script ?? "");
    expect(script).toContain("repo-auditor-report");
    expect(script).toContain("65500");
  });
});

describe("security scan workflows", () => {
  it("self-test workflow uses the action and asserts the Block decision", () => {
    const workflowPath = path.join(__dirname, "../../../.github/workflows/scan-self-test.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");

    expect(workflow).toContain("uses: ./");
    expect(workflow).toContain("target: fixtures/malicious-package");
    expect(workflow).toContain('fail-on-block: "false"');
    expect(workflow).toContain('"Block"');
  });

  it("example consumer workflow documents permissions and pr-comment", () => {
    const examplePath = path.join(__dirname, "../../../examples/security-scan.yml");
    const example = fs.readFileSync(examplePath, "utf8");

    expect(example).toContain("pull-requests: write");
    expect(example).toContain("contents: read");
    expect(example).toContain('pr-comment: "true"');
    expect(example).toContain("uses: OWNER/REPO@main");
  });
});
