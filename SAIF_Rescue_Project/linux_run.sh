#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ -x "$SCRIPT_DIR/.venv-linux/bin/python" ]; then
  exec "$SCRIPT_DIR/.venv-linux/bin/python" "$SCRIPT_DIR/main.py" "$@"
elif [ -x "$SCRIPT_DIR/.venv/bin/python" ]; then
  exec "$SCRIPT_DIR/.venv/bin/python" "$SCRIPT_DIR/main.py" "$@"
elif command -v python3 >/dev/null 2>&1 && python3 -c "import psutil, tkinter" >/dev/null 2>&1; then
  exec python3 "$SCRIPT_DIR/main.py" "$@"
else
  echo "HIKMA's Linux dependencies are missing. Run: bash setup_linux.sh" >&2
  exit 1
fi
