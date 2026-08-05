import { describe, expect, it, vi } from "vitest";
import { parseAgentResponse, runAgentLoop, estimateTokens, type AgentFinalResult } from "../src/agent.js";
import type { AiProviderConfig } from "../src/types.js";
import type { ToolDefinition, ReviewToolContext } from "../src/tools.js";

const config: AiProviderConfig = {
  type: "cloud",
  baseUrl: "https://api.example.test/v1",
  model: "gpt-test",
  dataSharingMode: "full-files",
  redactionEnabled: true,
  timeoutMs: 30000,
  retryLimit: 0
};

function jsonCompletion(content: string) {
  return vi.fn(async () => ({
    ok: true,
    status: 200,
    text: async () => "",
    json: async () => ({ choices: [{ message: { content } }] })
  }));
}

describe("parseAgentResponse", () => {
  it("parses a final response", () => {
    const parsed = parseAgentResponse(
      JSON.stringify({
        type: "final",
        summary: "done",
        notes: [{ findingId: "finding-1", explanation: "real risk", falsePositiveNote: "none" }]
      })
    );

    expect(parsed?.type).toBe("final");
    if (parsed?.type === "final") {
      expect(parsed.result.summary).toBe("done");
      expect(parsed.result.notes[0].findingId).toBe("finding-1");
    }
  });

  it("parses responses wrapped in code fences", () => {
    const parsed = parseAgentResponse("```json\n{\"type\":\"final\",\"summary\":\"s\",\"notes\":[]}\n```");
    expect(parsed?.type).toBe("final");
  });

  it("returns undefined for non-JSON text", () => {
    expect(parseAgentResponse("AI summary")).toBeUndefined();
  });
});

describe("runAgentLoop", () => {
  const ctx: ReviewToolContext = { scanPath: "", mode: "full-files" };
  const echoTool: ToolDefinition = {
    name: "echo_tool",
    description: "echoes args",
    run: async (args) => `echoed:${String(args.value)}`
  };

  it("executes a tool call then returns a final result", async () => {
    const fetchImpl = jsonCompletion(
      JSON.stringify({ type: "tool_call", tool: "echo_tool", args: { value: "abc" } })
    );
    const fetchFinal = jsonCompletion(
      JSON.stringify({ type: "final", summary: "done", notes: [{ findingId: "f1", explanation: "x" }] })
    );
    let callCount = 0;
    const fetch = vi.fn(async (...args: Parameters<typeof fetchFinal>) => {
      callCount += 1;
      return callCount === 1 ? await fetchImpl(...args) : await fetchFinal(...args);
    });

    const result = await runAgentLoop(config, "system", "initial", [echoTool], ctx, { maxRounds: 3, maxTokensPerReview: 100000 }, fetch);

    expect(result.result?.summary).toBe("done");
    expect(result.result?.notes[0].findingId).toBe("f1");
  });

  it("returns raw text when the model never emits valid JSON", async () => {
    const fetch = jsonCompletion("plain text that is not json");
    const result = await runAgentLoop(config, "system", "initial", [echoTool], ctx, { maxRounds: 2, maxTokensPerReview: 100000 }, fetch);

    expect(result.result).toBeUndefined();
    expect(result.raw).toBe("plain text that is not json");
  });

  it("respects the maxRounds cap", async () => {
    const fetch = jsonCompletion(JSON.stringify({ type: "tool_call", tool: "echo_tool", args: { value: "x" } }));
    const result = await runAgentLoop(config, "system", "initial", [echoTool], ctx, { maxRounds: 2, maxTokensPerReview: 100000 }, fetch);

    expect(result.result).toBeUndefined();
  });
});

describe("estimateTokens", () => {
  it("approximates tokens from character count", () => {
    expect(estimateTokens("abcde")).toBe(2);
    expect(estimateTokens("")).toBe(1);
  });
});
