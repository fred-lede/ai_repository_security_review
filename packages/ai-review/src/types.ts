import type { Finding } from "@repo-auditor/scanner-core";

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
  contextWindow?: number;
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
  newFindings: Finding[];
  truncated?: boolean;
}

export interface AiNewFinding {
  category: "phishing" | "network-attack" | "data-exfiltration";
  filePath: string;
  lineStart: number;
  lineEnd: number;
  codeSnippet: string;
  explanation: string;
  recommendedFix: string;
}

export interface AiReviewOptions {
  scanPath?: string;
  maxRounds?: number;
  maxFindingsPerBatch?: number;
  maxTokensPerReview?: number;
  maxTotalMs?: number;
  onBatchProgress?: (done: number, total: number) => void;
}
