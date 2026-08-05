#!/usr/bin/env bash
set -euo pipefail

APP_NAME="Repository Security Auditor.app"
APP_PATH=""

for dir in release/mac-arm64 release/mac; do
  if [ -d "$dir/$APP_NAME" ]; then
    APP_PATH="$dir/$APP_NAME"
    break
  fi
done

if [ -z "$APP_PATH" ]; then
  echo "error: $APP_NAME not found in release/mac or release/mac-arm64" >&2
  exit 1
fi

echo "ad-hoc signing: $APP_PATH"
codesign --force --deep --sign - "$APP_PATH"
xattr -dr com.apple.quarantine "$APP_PATH" 2>/dev/null || true
echo "done: $APP_PATH"
