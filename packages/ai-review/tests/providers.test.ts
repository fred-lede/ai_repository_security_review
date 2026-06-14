import { describe, expect, it, vi } from "vitest";
import { buildProviderRequest, listProviderModels, requestProviderCompletion } from "../src/providers.js";
import type { AiProviderConfig } from "../src/types.js";

const baseConfig: AiProviderConfig = {
  type: "ollama",
  baseUrl: "http://localhost:11434/",
  model: "llama3.1",
  dataSharingMode: "finding-snippets",
  redactionEnabled: true,
  timeoutMs: 30000,
  retryLimit: 1
};

describe("provider requests", () => {
  it("builds an Ollama request", () => {
    const request = buildProviderRequest(baseConfig, "Summarize risk");

    expect(request.url).toBe("http://localhost:11434/api/generate");
    expect(request.headers).toEqual({ "content-type": "application/json" });
    expect(request.body).toEqual({ model: "llama3.1", prompt: "Summarize risk", stream: false });
  });

  it("builds an OpenAI-compatible cloud request", () => {
    const request = buildProviderRequest(
      {
        ...baseConfig,
        type: "cloud",
        baseUrl: "https://api.example.test/v1",
        model: "gpt-test",
        apiKey: "secret-key"
      },
      "Summarize risk"
    );

    expect(request.url).toBe("https://api.example.test/v1/chat/completions");
    expect(request.headers.authorization).toBe("Bearer secret-key");
    expect(request.body).toEqual({
      model: "gpt-test",
      messages: [{ role: "user", content: "Summarize risk" }]
    });
  });

  it("extracts Ollama completion text through an injected fetch implementation", async () => {
    const fetchImpl = vi.fn(async () => ({
      ok: true,
      status: 200,
      text: async () => "",
      json: async () => ({ response: "review summary" })
    }));

    await expect(requestProviderCompletion(baseConfig, "prompt", fetchImpl)).resolves.toBe("review summary");
    expect(fetchImpl).toHaveBeenCalledWith(
      "http://localhost:11434/api/generate",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ model: "llama3.1", prompt: "prompt", stream: false })
      })
    );
  });

  it("extracts OpenAI-compatible completion text", async () => {
    const fetchImpl = vi.fn(async () => ({
      ok: true,
      status: 200,
      text: async () => "",
      json: async () => ({ choices: [{ message: { content: "cloud summary" } }] })
    }));

    await expect(
      requestProviderCompletion(
        { ...baseConfig, type: "custom", baseUrl: "https://llm.example.test/v1", model: "custom-model" },
        "prompt",
        fetchImpl
      )
    ).resolves.toBe("cloud summary");
  });

  it("lists installed Ollama models", async () => {
    const fetchImpl = vi.fn(async () => ({
      ok: true,
      status: 200,
      text: async () => "",
      json: async () => ({
        models: [
          { name: "llama3.1:latest", modified_at: "2026-01-01T00:00:00Z" },
          { name: "codellama:13b", modified_at: "2026-01-02T00:00:00Z" }
        ]
      })
    }));

    await expect(listProviderModels(baseConfig, fetchImpl)).resolves.toEqual([
      { id: "llama3.1:latest", label: "llama3.1:latest" },
      { id: "codellama:13b", label: "codellama:13b" }
    ]);
    expect(fetchImpl).toHaveBeenCalledWith(
      "http://localhost:11434/api/tags",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("lists OpenAI-compatible models", async () => {
    const fetchImpl = vi.fn(async () => ({
      ok: true,
      status: 200,
      text: async () => "",
      json: async () => ({
        data: [{ id: "gpt-4.1" }, { id: "o4-mini" }]
      })
    }));

    await expect(
      listProviderModels(
        { ...baseConfig, type: "cloud", baseUrl: "https://api.example.test/v1", apiKey: "secret-key" },
        fetchImpl
      )
    ).resolves.toEqual([
      { id: "gpt-4.1", label: "gpt-4.1" },
      { id: "o4-mini", label: "o4-mini" }
    ]);
    expect(fetchImpl).toHaveBeenCalledWith(
      "https://api.example.test/v1/models",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({ authorization: "Bearer secret-key" })
      })
    );
  });
});
