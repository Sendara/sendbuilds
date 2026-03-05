#!/usr/bin/env bash
# Universal installer for sendbuilds (Windows, Linux, macOS)
set -e

# ---------------------------
# Configuration
# ---------------------------
BIN_NAME="sendbuilds"
DEST="$HOME/.local/bin"

# Detect Windows
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    BIN_NAME="sendbuilds.exe"
    DEST="$HOME/bin"
fi

mkdir -p "$DEST"

# ---------------------------
# Detect OS and ARCH
# ---------------------------
OS="$(uname | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
if [[ "$ARCH" == "x86_64" || "$ARCH" == "amd64" ]]; then
    ARCH="x86_64"
else
    ARCH="i386"
fi

# ---------------------------
# Build download URL
# ---------------------------
URL="https://github.com/sendara/sendbuilds/releases/latest/download/sendbuilds-$OS-$ARCH$BIN_NAME"

echo "Downloading sendbuilds from $URL ..."
curl -fsSL "$URL" -o "$DEST/$BIN_NAME"

# ---------------------------
# Make executable on Unix
# ---------------------------
if [[ "$OSTYPE" != "msys" && "$OSTYPE" != "win32" ]]; then
    chmod +x "$DEST/$BIN_NAME"
fi

# ---------------------------
# Add DEST to PATH if missing
# ---------------------------
if [[ ":$PATH:" != *":$DEST:"* ]]; then
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        # Windows: add to user PATH via PowerShell
        powershell -NoProfile -Command "[Environment]::SetEnvironmentVariable('Path', [Environment]::GetEnvironmentVariable('Path','User') + ';$DEST','User')"
        echo "Added $DEST to User PATH. Restart terminal to use sendbuilds."
    else
        # Unix: add to shell profile
        SHELL_RC="$HOME/.profile"
        if [[ ! -f "$SHELL_RC" ]]; then
            touch "$SHELL_RC"
        fi
        if ! grep -Fxq "export PATH=\"$DEST:\$PATH\"" "$SHELL_RC"; then
            echo "export PATH=\"$DEST:\$PATH\"" >> "$SHELL_RC"
            echo "Added $DEST to PATH. Reload shell or source ~/.profile."
        fi
        export PATH="$DEST:$PATH"
    fi
fi

# ---------------------------
# Verify
# ---------------------------
if command -v sendbuilds >/dev/null 2>&1; then
    echo ""
    echo "sendbuilds installed successfully!"
    echo "Run: sendbuilds -h"
else
    echo ""
    echo "Installed but not detected in this session yet."
    echo "Try: $DEST/$BIN_NAME -h"
    echo "Then open a NEW terminal."
fi