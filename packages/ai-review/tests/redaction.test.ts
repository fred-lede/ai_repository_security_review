import { describe, expect, it } from "vitest";
import { redactSecrets } from "../src/redaction.js";

describe("redactSecrets", () => {
  it("redacts common token values", () => {
    const input = [
      "TELEGRAM_BOT_TOKEN=123456:ABCdefSecretValueABCdefSecretValue",
      "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456",
      "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456",
      "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP",
      "password=hunter2"
    ].join("\n");

    const redacted = redactSecrets(input);

    expect(redacted).toContain("[REDACTED_TELEGRAM_TOKEN]");
    expect(redacted).toContain("[REDACTED_GITHUB_TOKEN]");
    expect(redacted).toContain("[REDACTED_API_KEY]");
    expect(redacted).toContain("[REDACTED_AWS_ACCESS_KEY]");
    expect(redacted).toContain("password=[REDACTED_SECRET]");
    expect(redacted).not.toContain("hunter2");
  });
});
