#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  sudo ./flash_usb.sh --iso /path/to/image.iso --device /dev/sdX

Options:
  --iso      Path to the distro ISO or disk image
  --device   USB block device to write to, such as /dev/sdb
  --yes      Skip the confirmation prompt

Example:
  sudo ./flash_usb.sh --iso ./linux.iso --device /dev/sdX --yes
EOF
}

ISO=""
DEVICE=""
AUTO_CONFIRM=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iso)
      ISO="${2:-}"
      shift 2
      ;;
    --device)
      DEVICE="${2:-}"
      shift 2
      ;;
    --yes)
      AUTO_CONFIRM=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$ISO" || -z "$DEVICE" ]]; then
  usage >&2
  exit 1
fi

if [[ ! -f "$ISO" ]]; then
  echo "ISO/image not found: $ISO" >&2
  exit 1
fi

if [[ ! -b "$DEVICE" ]]; then
  echo "Device is not a block device: $DEVICE" >&2
  echo "Available devices:" >&2
  lsblk -d -o NAME,SIZE,TYPE,MODEL >&2 || true
  exit 1
fi

DEVICE_TYPE="$(lsblk -dnro TYPE "$DEVICE" 2>/dev/null || true)"
if [[ "$DEVICE_TYPE" != "disk" ]]; then
  echo "The target must be a whole disk device, not a partition: $DEVICE" >&2
  lsblk -d -o NAME,SIZE,TYPE,MODEL >&2 || true
  exit 1
fi

if lsblk -nrpo MOUNTPOINT "$DEVICE" | grep -q '[^[:space:]]'; then
  echo "The target disk or one of its partitions is mounted. Unmount it before flashing: $DEVICE" >&2
  lsblk -o NAME,SIZE,TYPE,MOUNTPOINTS,MODEL "$DEVICE" >&2 || true
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root or with sudo." >&2
  exit 1
fi

if [[ "$AUTO_CONFIRM" -ne 1 ]]; then
  echo "WARNING: This will completely erase: $DEVICE"
  echo "Source image: $ISO"
  read -r -p "Type 'FLASH' to continue: " CONFIRM
  if [[ "$CONFIRM" != "FLASH" ]]; then
    echo "Aborted. No data was written." >&2
    exit 1
  fi
fi

echo "Writing image to $DEVICE ..."
dd if="$ISO" of="$DEVICE" bs=4M status=progress conv=fsync
sync

echo "Flash complete."
echo "You can safely remove the USB device."
