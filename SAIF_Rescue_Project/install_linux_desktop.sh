#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_MODE="user"
if [ "${1:-}" = "--system" ]; then
  TARGET_MODE="system"
fi

if [ "$TARGET_MODE" = "system" ]; then
  DESKTOP_DIR="/usr/share/applications"
  BIN_DIR="/usr/local/bin"
  sudo mkdir -p "$DESKTOP_DIR" "$BIN_DIR"
  sudo install -m 755 "$SCRIPT_DIR/linux_run.sh" "$BIN_DIR/hikma-rescue"
  sudo install -m 644 "$SCRIPT_DIR/hikma-rescue.desktop" "$DESKTOP_DIR/hikma-rescue.desktop"
  sudo ln -sf "$BIN_DIR/hikma-rescue" "$BIN_DIR/hikma-rescue"
  cho "Installed HIKMA Rescue Engine for all users."
else
  DESKTOP_DIR="$HOME/.local/share/applications"
  BIN_DIR="$HOME/.local/bin"
  mkdir -p "$DESKTOP_DIR" "$BIN_DIR"
  install -m 755 "$SCRIPT_DIR/linux_run.sh" "$BIN_DIR/hikma-rescue"
  install -m 644 "$SCRIPT_DIR/hikma-rescue.desktop" "$DESKTOP_DIR/hikma-rescue.desktop"
  sed -i "s|^Exec=.*|Exec=$BIN_DIR/hikma-rescue|" "$DESKTOP_DIR/hikma-rescue.desktop"
  sed -i "s|^TryExec=.*|TryExec=$BIN_DIR/hikma-rescue|" "$DESKTOP_DIR/hikma-rescue.desktop"
  echo "Installed HIKMA Rescue Engine for the current user."
fi

printf '\nYou can now launch it from the app menu or run:\n'
printf '  %s\n' "$BIN_DIR/hikma-rescue"
