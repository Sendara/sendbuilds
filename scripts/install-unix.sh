#!/usr/bin/env sh
set -eu

BIN_NAME="sendbuilds"
SRC_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
SRC_BIN="$SRC_DIR/$BIN_NAME"

if [ ! -f "$SRC_BIN" ]; then
  echo "sendbuilds binary not found next to install-unix.sh"
  exit 1
fi

DEFAULT_DEST="${HOME}/.local/bin"
DEST_DIR="${1:-$DEFAULT_DEST}"
DEST_BIN="$DEST_DIR/$BIN_NAME"

mkdir -p "$DEST_DIR"
cp "$SRC_BIN" "$DEST_BIN"
chmod +x "$DEST_BIN"

echo "Installed: $DEST_BIN"
case ":$PATH:" in
  *":$DEST_DIR:"*) echo "PATH already includes $DEST_DIR" ;;
  *)
    echo ""
    echo "Add this to your shell profile:"
    echo "  export PATH=\"$DEST_DIR:\$PATH\""
    ;;
esac
