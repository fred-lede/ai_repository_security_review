export const allowedIpcChannels = [
  "scan:start",
  "scan:cancel",
  "report:read",
  "report:export",
  "ai-review:run",
  "folder:open"
] as const;

export type AllowedIpcChannel = (typeof allowedIpcChannels)[number];

export function isAllowedIpcChannel(channel: string): channel is AllowedIpcChannel {
  return (allowedIpcChannels as readonly string[]).includes(channel);
}
