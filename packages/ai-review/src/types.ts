export type AiProviderType = "cloud" | "ollama" | "custom";
export type AiDataSharingMode = "metadata-only" | "finding-snippets" | "full-files";

export type AiLanguage = "en" | "zh-TW" | "zh-CN";

export interface AiProviderConfig {
  type: AiProviderType;
  baseUrl: string;
  model: string;
  apiKey?: string;
  dataSharingMode: AiDataSharingMode;
  redactionEnabled: boolean;
  timeoutMs: number;
  retryLimit: number;
  language?: AiLanguage;
}

export interface AiReviewResult {
  providerType: AiProviderType;
  model: string;
  generatedAt: string;
  summary: string;
  findingNotes: Array<{
    findingId: string;
    explanation: string;
    falsePositiveNote?: string;
    saferPattern?: string;
  }>;
}
