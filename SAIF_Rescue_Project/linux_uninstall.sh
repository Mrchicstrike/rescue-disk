#!/usr/bin/env bash
set -euo pipefail

for target in \
  "$HOME/.local/share/applications/hikma-rescue.desktop" \
  "$HOME/.local/bin/hikma-rescue" \
  "/usr/share/applications/hikma-rescue.desktop" \
  "/usr/local/bin/hikma-rescue"; do
  [ -e "$target" ] && rm -f "$target"
done

printf 'HIKMA Rescue Engine launcher removed.\n'
