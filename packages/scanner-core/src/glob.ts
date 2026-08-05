function escapeRegexChar(ch: string): string {
  return ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function globToRegExp(pattern: string): RegExp {
  let re = "";
  let i = 0;
  const n = pattern.length;

  while (i < n) {
    const ch = pattern[i];
    if (ch === "*") {
      if (pattern[i + 1] === "*") {
        i += 2;
        if (pattern[i] === "/") {
          re += "(?:.*/)?";
          i += 1;
        } else {
          re += ".*";
        }
      } else {
        re += "[^/]*";
        i += 1;
      }
    } else if (ch === "?") {
      re += "[^/]";
      i += 1;
    } else if (ch === "{") {
      const end = pattern.indexOf("}", i);
      if (end > i) {
        const options = pattern
          .slice(i + 1, end)
          .split(",")
          .map((opt) => escapeRegexChar(opt))
          .join("|");
        re += `(?:${options})`;
        i = end + 1;
      } else {
        re += "\\{";
        i += 1;
      }
    } else if (ch === "\\") {
      re += escapeRegexChar(pattern[i + 1] ?? "");
      i += 2;
    } else {
      re += escapeRegexChar(ch);
      i += 1;
    }
  }

  return new RegExp(`^${re}$`);
}

export function matchesGlob(pattern: string, filePath: string): boolean {
  return globToRegExp(pattern).test(filePath);
}
