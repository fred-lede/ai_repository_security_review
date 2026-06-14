import type { AiProviderConfig } from "./types.js";

export interface ProviderRequest {
  url: string;
  headers: Record<string, string>;
  body: Record<string, unknown>;
  timeoutMs: number;
  retryLimit: number;
}

export interface ProviderModel {
  id: string;
  label: string;
}

export type FetchLike = (
  input: string,
  init: {
    method: "GET" | "POST";
    headers: Record<string, string>;
    body?: string;
    signal?: AbortSignal;
  }
) => Promise<{
  ok: boolean;
  status: number;
  text: () => Promise<string>;
  json: () => Promise<unknown>;
}>;

export function buildProviderRequest(config: AiProviderConfig, prompt: string): ProviderRequest {
  const baseUrl = config.baseUrl.replace(/\/$/, "");

  if (config.type === "ollama") {
    return {
      url: `${baseUrl}/api/generate`,
      headers: { "content-type": "application/json" },
      body: { model: config.model, prompt, stream: false },
      timeoutMs: config.timeoutMs,
      retryLimit: config.retryLimit
    };
  }

  return {
    url: `${baseUrl}/chat/completions`,
    headers: {
      "content-type": "application/json",
      ...(config.apiKey ? { authorization: `Bearer ${config.apiKey}` } : {})
    },
    body: {
      model: config.model,
      messages: [{ role: "user", content: prompt }]
    },
    timeoutMs: config.timeoutMs,
    retryLimit: config.retryLimit
  };
}

export async function listProviderModels(
  config: Pick<AiProviderConfig, "type" | "baseUrl" | "apiKey" | "timeoutMs">,
  fetchImpl: FetchLike = globalThis.fetch as FetchLike
): Promise<ProviderModel[]> {
  const baseUrl = config.baseUrl.replace(/\/$/, "");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), config.timeoutMs);

  try {
    const response = await fetchImpl(config.type === "ollama" ? `${baseUrl}/api/tags` : `${baseUrl}/models`, {
      method: "GET",
      headers: {
        "content-type": "application/json",
        ...(config.type !== "ollama" && config.apiKey ? { authorization: `Bearer ${config.apiKey}` } : {})
      },
      signal: controller.signal
    });

    if (!response.ok) {
      throw new Error(`Provider model request failed with HTTP ${response.status}: ${await response.text()}`);
    }

    return extractProviderModels(config.type, await response.json());
  } finally {
    clearTimeout(timeout);
  }
}

export async function requestProviderCompletion(
  config: AiProviderConfig,
  prompt: string,
  fetchImpl: FetchLike = globalThis.fetch as FetchLike
): Promise<string> {
  const request = buildProviderRequest(config, prompt);
  let lastError: unknown;

  for (let attempt = 0; attempt <= request.retryLimit; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), request.timeoutMs);

    try {
      const response = await fetchImpl(request.url, {
        method: "POST",
        headers: request.headers,
        body: JSON.stringify(request.body),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`Provider request failed with HTTP ${response.status}: ${await response.text()}`);
      }

      return extractCompletionText(config.type, await response.json());
    } catch (error) {
      lastError = error;
    } finally {
      clearTimeout(timeout);
    }
  }

  throw lastError instanceof Error ? lastError : new Error("Provider request failed");
}

function extractProviderModels(providerType: AiProviderConfig["type"], payload: unknown): ProviderModel[] {
  if (!isRecord(payload)) {
    throw new Error("Provider returned a non-object model response");
  }

  if (providerType === "ollama") {
    const models = payload.models;
    if (!Array.isArray(models)) {
      return [];
    }

    return models
      .map((model) => (isRecord(model) && typeof model.name === "string" ? model.name : undefined))
      .filter((name): name is string => Boolean(name))
      .map((name) => ({ id: name, label: name }));
  }

  const data = payload.data;
  if (!Array.isArray(data)) {
    return [];
  }

  return data
    .map((model) => (isRecord(model) && typeof model.id === "string" ? model.id : undefined))
    .filter((id): id is string => Boolean(id))
    .map((id) => ({ id, label: id }));
}

function extractCompletionText(providerType: AiProviderConfig["type"], payload: unknown): string {
  if (!isRecord(payload)) {
    throw new Error("Provider returned a non-object response");
  }

  if (providerType === "ollama") {
    const response = payload.response;
    if (typeof response === "string") {
      return response;
    }
  }

  const choices = payload.choices;
  if (Array.isArray(choices)) {
    const first = choices[0];
    if (isRecord(first) && isRecord(first.message) && typeof first.message.content === "string") {
      return first.message.content;
    }
  }

  throw new Error("Provider response did not include completion text");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
