import { describe, expect, it, vi } from "vitest";
import { parseAgentResponse, runAgentLoop, estimateTokens, buildAgentPrompt, type AgentFinalResult } from "../src/agent.js";
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

  it("normalizes common note key aliases instead of dropping notes", () => {
    const parsed = parseAgentResponse(
      JSON.stringify({
        type: "final",
        summary: "reviewed",
        notes: [
          { finding_id: "finding-1", explanation: "real risk" },
          { id: "finding-2", explanation: "likely false positive" },
          { findingID: "finding-3", explanation: "confirmed" }
        ]
      })
    );

    expect(parsed?.type).toBe("final");
    if (parsed?.type === "final") {
      expect(parsed.result.notes).toHaveLength(3);
      expect(parsed.result.notes[0].findingId).toBe("finding-1");
      expect(parsed.result.notes[1].findingId).toBe("finding-2");
      expect(parsed.result.notes[2].findingId).toBe("finding-3");
    }
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

describe("newFindings and history pruning", () => {
  it("parses newFindings from a final response", () => {
    const parsed = parseAgentResponse(
      JSON.stringify({
        type: "final",
        summary: "found an exfil sink",
        notes: [],
        newFindings: [
          {
            category: "data-exfiltration",
            filePath: "scripts/upload.ts",
            lineStart: 3,
            lineEnd: 3,
            codeSnippet: "fetch(discordWebhook)",
            explanation: "verified webhook sink sending local files",
            recommendedFix: "remove the webhook call"
          }
        ]
      })
    );

    expect(parsed?.type).toBe("final");
    if (parsed?.type === "final") {
      expect(parsed.result.newFindings).toHaveLength(1);
      expect(parsed.result.newFindings[0].category).toBe("data-exfiltration");
      expect(parsed.result.newFindings[0].filePath).toBe("scripts/upload.ts");
    }
  });

  it("prunes oldest tool results when the prompt exceeds the budget", async () => {
    let callCount = 0;
    const fetchImpl = vi.fn(async () => {
      callCount += 1;
      if (callCount === 1) {
        return {
          ok: true,
          status: 200,
          text: async () => "",
          json: async () => ({
            choices: [
              {
                message: {
                  content: JSON.stringify({
                    type: "tool_call",
                    tool: "file_read",
                    args: { path: "test.txt" }
                  })
                }
              }
            ]
          })
        };
      }
      return {
        ok: true,
        status: 200,
        text: async () => "",
        json: async () => ({
          choices: [
            {
              message: {
                content: JSON.stringify({ type: "final", summary: "done", notes: [] })
              }
            }
          ]
        })
      };
    });

    const config: AiProviderConfig = {
      type: "cloud",
      baseUrl: "https://api.example.test/v1",
      model: "gpt-test",
      dataSharingMode: "full-files",
      redactionEnabled: true,
      timeoutMs: 30000,
      retryLimit: 0,
      contextWindow: 1024
    };
    const tools: ToolDefinition[] = [
      {
        name: "file_read",
        description: "read a file",
        run: async () => "x".repeat(2000)
      }
    ];
    const result = await runAgentLoop(
      config,
      "system",
      "review this",
      tools,
      { scanPath: "/tmp", mode: "full-files" },
      { maxRounds: 10, maxTokensPerReview: 4000 },
      fetchImpl
    );

    expect(result.result?.summary).toBe("done");
  });
});

describe("custom final schema via parseResponse + finalExample", () => {
  const ctx: ReviewToolContext = { scanPath: "", mode: "full-files" };

  it("builds prompts with a custom final schema example", () => {
    const prompt = buildAgentPrompt(
      "sys",
      [],
      ["initial"],
      '{"type":"final","verdict":"real|false-positive|uncertain","analysis":"...","fixSteps":[...],"correctedCode":"..."}'
    );
    expect(prompt).toContain('"verdict"');
    expect(prompt).not.toContain('"newFindings"');
  });

  it("returns a custom-shaped final result from a custom parser", async () => {
    const fetchImpl = jsonCompletion(
      JSON.stringify({ type: "final", verdict: "real", analysis: "confirmed", fixSteps: [], correctedCode: "" })
    );
    const result = await runAgentLoop(
      config,
      "system",
      "initial",
      [],
      ctx,
      {
        maxRounds: 1,
        maxTokensPerReview: 100000,
        parseResponse: (text: string) => {
          const parsed = JSON.parse(text) as Record<string, unknown>;
          if (parsed.type === "final") {
            return { type: "final", result: { verdict: String(parsed.verdict) } };
          }
          return undefined;
        },
        finalExample: '{"type":"final","verdict":"real"}'
      },
      fetchImpl
    );
    expect(result.result).toEqual({ verdict: "real" });
  });
});
