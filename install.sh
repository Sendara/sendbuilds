#!/usr/bin/env bash
set -euo pipefail

# ----------------------
# Configuration
# ----------------------
REPO_OWNER="Sendara"
REPO_NAME="sendbuilds"
VERSION="v0.1.0-beta"  # fallback; you can override with SENDBUILDS_VERSION env
BIN_NAME="sendbuilds"
BIN_DIR="${BIN_DIR:-}"
CURL_RETRY_OPTS="--retry 3 --retry-all-errors --retry-delay 2"

# ----------------------
# Logging helpers
# ----------------------
info() { printf "[INFO] %s\n" "$*"; }
warn() { printf "[WARN] %s\n" "$*"; }
error() { printf "[ERROR] %s\n" "$*" >&2; exit 1; }

# ----------------------
# Detect platform & arch
# ----------------------
detect_platform() {
  unameOut="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$unameOut" in
    msys*|cygwin*|mingw*) echo "pc-windows-gnu" ;;
    linux) echo "unknown-linux-gnu" ;;
    darwin) echo "apple-darwin" ;;
    *) error "Unsupported OS: $unameOut" ;;
  esac
}

detect_arch() {
  arch="$(uname -m | tr '[:upper:]' '[:lower:]')"
  case "$arch" in
    x86_64|amd64) echo "x86_64" ;;
    aarch64|arm64) echo "aarch64" ;;
    i686|i386) echo "i686" ;;
    *) error "Unsupported architecture: $arch" ;;
  esac
}

PLATFORM="${PLATFORM:-$(detect_platform)}"
ARCH="${ARCH:-$(detect_arch)}"
TARGET="${ARCH}-${PLATFORM}"

# On Windows Git Bash/MSYS, install to a stable user-local folder by default.
if [[ "$PLATFORM" == "pc-windows-gnu" && -z "${BIN_DIR:-}" ]]; then
  BIN_DIR="${HOME}/.sendbuilds/bin"
fi
if [[ -z "${BIN_DIR:-}" ]]; then
  BIN_DIR="${HOME}/bin"
fi

info "Detected platform: $PLATFORM"
info "Detected architecture: $ARCH"
info "Target: $TARGET"

# ----------------------
# Determine URLs
# ----------------------
VERSION="${SENDBUILDS_VERSION:-$VERSION}"
BASE_URL="https://github.com/$REPO_OWNER/$REPO_NAME/releases/download/$VERSION"
EXT=""

if [[ "$PLATFORM" == "pc-windows-gnu" ]]; then
  EXT=".exe"
fi

BINARY_URL="$BASE_URL/$BIN_NAME-$TARGET$EXT"
SHA_URL="$BINARY_URL.sha256"

info "Release URL: $BINARY_URL"
info "SHA256 URL: $SHA_URL"

# ----------------------
# Prepare directories
# ----------------------
mkdir -p "$BIN_DIR"

# ----------------------
# Temp files (Windows-safe)
# ----------------------
TMP_BIN="$(mktemp -t "${BIN_NAME}.XXXXXX${EXT}")"
TMP_SHA="$(mktemp -t "${BIN_NAME}.XXXXXX.sha256")"

cleanup() {
  rm -f "$TMP_BIN" "$TMP_SHA"
}
trap cleanup EXIT

to_windows_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$1"
  else
    printf "%s" "$1"
  fi
}

# ----------------------
# Download binary and SHA
# ----------------------
info "Downloading binary..."
curl -fsSL $CURL_RETRY_OPTS -o "$TMP_BIN" "$BINARY_URL" || error "Failed to download binary"
info "Downloading SHA256..."
curl -fsSL $CURL_RETRY_OPTS -o "$TMP_SHA" "$SHA_URL" || error "Failed to download SHA256"

# ----------------------
# Verify checksum
# ----------------------
info "Verifying SHA256..."
cd "$(dirname "$TMP_BIN")"
SHA_EXPECTED="$(awk '{print $1}' "$TMP_SHA" | tr -d '\r\n')"
SHA_ACTUAL="$(
  (
    sha256sum "$(basename "$TMP_BIN")" 2>/dev/null \
      || shasum -a 256 "$(basename "$TMP_BIN")"
  ) | awk '{print $1}' | tr -d '\r\n'
)"

if [[ "$SHA_EXPECTED" != "$SHA_ACTUAL" ]]; then
  error "SHA256 mismatch! Expected $SHA_EXPECTED, got $SHA_ACTUAL"
fi
info "SHA256 verified successfully"

# ----------------------
# Install binary
# ----------------------
DEST_BIN="$BIN_DIR/$BIN_NAME$EXT"
info "Installing to $DEST_BIN..."
mv "$TMP_BIN" "$DEST_BIN"
chmod +x "$DEST_BIN"
info "Installed $BIN_NAME successfully!"

# Keep PowerShell/cmd in sync on Windows by updating user PATH.
if [[ "$PLATFORM" == "pc-windows-gnu" ]]; then
  WIN_BIN_DIR="$(to_windows_path "$BIN_DIR")"
  WIN_BIN_DIR_ESCAPED="${WIN_BIN_DIR//\'/\'\'}"
  powershell.exe -NoProfile -NonInteractive -Command "
    \$bin = '$WIN_BIN_DIR_ESCAPED'
    \$path = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ([string]::IsNullOrWhiteSpace(\$path)) {
      [Environment]::SetEnvironmentVariable('Path', \$bin, 'User')
      exit 0
    }
    \$parts = \$path -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace(\$_) }
    if (\$parts -contains \$bin) { exit 0 }
    [Environment]::SetEnvironmentVariable('Path', (\$path.TrimEnd(';') + ';' + \$bin), 'User')
  " >/dev/null 2>&1 || warn "Failed to update Windows PATH automatically. Add $WIN_BIN_DIR manually to your User PATH."
fi

# ----------------------
# PATH warning
# ----------------------
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
  warn "$BIN_DIR is not in your PATH."
  if [[ "$PLATFORM" == "pc-windows-gnu" ]]; then
    info "Open a new PowerShell/cmd window after install. If needed, add $(to_windows_path "$BIN_DIR") to your User PATH."
  else
    info "Add the following line to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
    echo "  export PATH=\"$BIN_DIR:\$PATH\""
  fi
fi

info "Installation complete! You can now run '$BIN_NAME --help'"