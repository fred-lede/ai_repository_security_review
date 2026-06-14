export function redactSecrets(input: string): string {
  return input
    .replace(/\b\d{5,}:[A-Za-z0-9_-]{20,}\b/g, "[REDACTED_TELEGRAM_TOKEN]")
    .replace(/\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b/g, "[REDACTED_GITHUB_TOKEN]")
    .replace(/\bsk-[A-Za-z0-9]{20,}\b/g, "[REDACTED_API_KEY]")
    .replace(/\bAKIA[A-Z0-9]{16}\b/g, "[REDACTED_AWS_ACCESS_KEY]")
    .replace(
      /(password|passwd|pwd|token|secret|api[_-]?key|authorization)\s*[:=]\s*["']?(?!\[REDACTED_)[^"'\s,}]+/gi,
      "$1=[REDACTED_SECRET]"
    );
}
