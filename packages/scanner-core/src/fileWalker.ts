import fg from "fast-glob";

export async function listScannableFiles(rootDir: string): Promise<string[]> {
  return fg(
    [
      "**/*.{js,jsx,ts,tsx,mjs,cjs,json,yml,yaml,sh,bash,zsh,Dockerfile}",
      ".github/workflows/*.{yml,yaml}"
    ],
    {
      cwd: rootDir,
      dot: true,
      onlyFiles: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", "coverage/**"]
    }
  );
}
