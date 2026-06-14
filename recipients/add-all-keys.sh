#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEY_DIR="$SCRIPT_DIR/keys"

if [ ! -d "$KEY_DIR" ]; then
  echo "Error: keys directory not found at $KEY_DIR" >&2
  exit 1
fi

added=0
skipped=0
for f in "$KEY_DIR"/*.asc; do
  [ -f "$f" ] || continue
  base="$(basename "$f" .asc)"
  namefile="${f%.asc}.name"
  name=""
  [ -f "$namefile" ] && name="$(cat "$namefile" | tr -d '\n')"

  if [ -n "$name" ]; then
    if sudo kblockerctl add-pgp "$f" "$name"; then
      added=$((added + 1))
    else
      skipped=$((skipped + 1))
    fi
  else
    if sudo kblockerctl add-pgp "$f"; then
      added=$((added + 1))
    else
      skipped=$((skipped + 1))
    fi
  fi
done

echo "Done. Added: $added, Skipped: $skipped"

