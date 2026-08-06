import type { ThreatFamily, ThreatSignal } from "./types.js";

interface ThreatPattern {
  id: string;
  family: ThreatFamily;
  regex: RegExp;
  tags: string[];
}

const THREAT_PATTERNS: ThreatPattern[] = [
  {
    id: "reverse-shell-dev-tcp",
    family: "network-attack",
    regex: /\/dev\/tcp\//,
    tags: ["network-attack", "reverse-shell"]
  },
  {
    id: "reverse-shell-nc",
    family: "network-attack",
    regex: /\bnc(?:at)?\s+[^\n]*-e\s+\/(?:bin|usr)\/(?:ba)?sh/,
    tags: ["network-attack", "reverse-shell"]
  },
  {
    id: "bind-shell",
    family: "network-attack",
    regex: /\bnc(?:at)?\s+-l[^\n]*|socat\s+TCP-LISTEN/,
    tags: ["network-attack", "bind-shell"]
  },
  {
    id: "ssrf-sink",
    family: "network-attack",
    regex: /(?:requests\.(?:get|post|request)\(\s*[^"']|urllib(?:\.request)?\.urlopen\(\s*[^"']|fetch\(\s*[a-zA-Z_$]|axios\.(?:get|post|request)\(\s*[^"'])/,
    tags: ["network-attack", "ssrf"]
  },
  {
    id: "port-scan",
    family: "network-attack",
    regex: /\bconnect_ex\s*\(|nmap|masscan/,
    tags: ["network-attack", "port-scan"]
  },
  {
    id: "credential-harvest",
    family: "phishing",
    regex: /getElementById(?:By(?:Tag|Class)Name)?\(\s*['"]password|localStorage|chrome\.(?:storage|cookies)/,
    tags: ["phishing", "credential-harvesting"]
  },
  {
    id: "keylogger",
    family: "phishing",
    regex: /\baddEventListener\(\s*['"]keydown|pynput|hook_all/,
    tags: ["phishing", "keylogger"]
  },
  {
    id: "bulk-email",
    family: "phishing",
    regex: /\bsmtplib\.SMTP\s*\(|nodemailer\.createTransport|sendmail\b/,
    tags: ["phishing", "bulk-email"]
  },
  {
    id: "webhook-sink",
    family: "data-exfiltration",
    regex: /discord\.com\/api\/webhooks|api\.telegram\.org|hooks\.slack\.com|webhook\.site|requestbin/,
    tags: ["data-exfiltration", "webhook"]
  },
  {
    id: "encoded-sink",
    family: "data-exfiltration",
    regex: /\bbase64\s+(?:-d|--decode)[^\n]*\|\s*(?:curl|nc|wget)|\b(?:btoa|atob)\s*\(|Buffer\.from\([^,]+,\s*['"]base64['"]\)/,
    tags: ["data-exfiltration", "encoded"]
  },
  {
    id: "non-http-sink",
    family: "data-exfiltration",
    regex: /\b(?:nc|ncat|socat|scp|rsync)\b[^\n]*(?:[0-9]{1,3}\.){3}[0-9]{1,3}|\b(?:nc|ncat|socat)\b[^\n]*\s+\d{4,5}\b|\b(?:ftp|sftp)\s+[^\s]+/,
    tags: ["data-exfiltration", "non-http"]
  },
  {
    id: "file-upload-sink",
    family: "data-exfiltration",
    regex: /\bcurl\s+[^\n]*(?:-d\s+@|-F\s+[^\s]*@)/,
    tags: ["data-exfiltration", "file-upload"]
  }
];

export function collectThreatSignals(content: string, filePath: string): ThreatSignal[] {
  const signals: ThreatSignal[] = [];

  content.split(/\r?\n/).forEach((lineText, index) => {
    for (const pattern of THREAT_PATTERNS) {
      if (pattern.regex.test(lineText)) {
        signals.push({
          family: pattern.family,
          pattern: pattern.id,
          filePath,
          line: index + 1,
          snippet: lineText.trim(),
          evidenceTags: pattern.tags
        });
      }
    }
  });

  return signals;
}
