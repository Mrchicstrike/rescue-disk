#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v apt-get >/dev/null 2>&1; then
  echo "This setup script supports Debian/Ubuntu-based Linux systems with apt-get." >&2
  exit 1
fi

if [ "$(id -u)" -eq 0 ]; then
  SUDO=()
elif command -v sudo >/dev/null 2>&1; then
  SUDO=(sudo)
else
  echo "Install sudo or run this script as root." >&2
  exit 1
fi

"${SUDO[@]}" apt-get update
"${SUDO[@]}" apt-get install -y python3 python3-venv python3-tk python3-psutil

python3 -c "import psutil, tkinter; print('Python, Tkinter, and psutil are ready.')"

chmod +x "$SCRIPT_DIR/linux_run.sh"
echo "HIKMA is ready. Launch with: $SCRIPT_DIR/linux_run.sh"
echo "For a read-only scan without a size limit: $SCRIPT_DIR/linux_run.sh --scan /path/to/folder --max-size-mb 0 --no-quarantine"