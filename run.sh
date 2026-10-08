#!/bin/sh
# Universal launcher for netconfig: auto-detects OS & architecture and executes the appropriate binary.

OS=""
ARCH=""

case "$(uname -s)" in
    Linux*)     OS="linux";;
    Darwin*)    OS="darwin";;
    CYGWIN*|MINGW*|MSYS*) OS="windows";;
    *)          echo "Error: Unsupported OS $(uname -s)"; exit 1;;
esac

case "$(uname -m)" in
    x86_64|amd64)  ARCH="amd64";;
    arm64|aarch64) ARCH="arm64";;
    *)             echo "Error: Unsupported Architecture $(uname -m)"; exit 1;;
esac

BINARY="bin/netconfig-${OS}-${ARCH}"
if [ "$OS" = "windows" ]; then
    BINARY="${BINARY}.exe"
fi

if [ ! -f "$BINARY" ]; then
    echo "Binary $BINARY not found. Building..."
    if command -v make >/dev/null 2>&1; then
        make build
        BINARY="bin/netconfig"
    else
        echo "Error: Binary $BINARY not found and make is unavailable."
        exit 1
    fi
fi

exec "$BINARY" "$@"
