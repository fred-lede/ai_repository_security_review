export const allowedIpcChannels = [
  "scan:start",
  "scan:cancel",
  "report:read",
  "report:export",
  "ai-review:run",
  "ai-models:list",
  "ai-connection:test",
  "folder:open",
  "rules:load",
  "rules:save",
  "key:save",
  "key:load",
  "key:delete",
  "source:read"
] as const;

export type AllowedIpcChannel = (typeof allowedIpcChannels)[number];

export function isAllowedIpcChannel(channel: string): channel is AllowedIpcChannel {
  return (allowedIpcChannels as readonly string[]).includes(channel);
}
