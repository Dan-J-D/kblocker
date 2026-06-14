#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEY_DIR="$SCRIPT_DIR/keys"
SYS_KEY_DIR="/etc/kblocker/keys"

if [ ! -d "$SYS_KEY_DIR" ]; then
  echo "Error: $SYS_KEY_DIR not found" >&2
  exit 1
fi

mkdir -p "$KEY_DIR"

copied=0
skipped=0
for f in "$SYS_KEY_DIR"/*.asc; do
  [ -f "$f" ] || continue
  base="$(basename "$f")"
  dest="$KEY_DIR/$base"
  if [ -f "$dest" ]; then
    skipped=$((skipped + 1))
    continue
  fi
  cp "$f" "$dest"

  namefile="${f%.asc}.name"
  if [ -f "$namefile" ]; then
    cp "$namefile" "$KEY_DIR/"
  fi

  echo "Copied: $base"
  copied=$((copied + 1))
done

echo "Done. Copied: $copied, Already exists: $skipped"
