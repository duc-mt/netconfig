#!/bin/sh
# ==============================================================================
# Script Name:   run.sh
# Description:   Implementation and logic for run.
# Author:        Mai Tan Duc <ducmai.network@gmail.com>
# Created:       2026-10-10
# Version:       1.0.0
# License:       MIT
# ==============================================================================
# Usage:         ./run.sh [options] [arguments]
# Notes:         Automated bash utility script
# ==============================================================================
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

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

BINARY="$ROOT_DIR/bin/netconfig"
[ "$OS" = "windows" ] && BINARY="$ROOT_DIR/bin/netconfig.exe"

ARCH_BINARY="$ROOT_DIR/bin/netconfig-${OS}-${ARCH}"
[ "$OS" = "windows" ] && ARCH_BINARY="${ARCH_BINARY}.exe"

ROOT_BIN="$ROOT_DIR/netconfig"
[ "$OS" = "windows" ] && ROOT_BIN="$ROOT_DIR/netconfig.exe"

ROOT_ARCH_BIN="$ROOT_DIR/netconfig-${OS}-${ARCH}"
[ "$OS" = "windows" ] && ROOT_ARCH_BIN="${ROOT_ARCH_BIN}.exe"

if [ -f "$BINARY" ]; then
    :
elif [ -f "$ARCH_BINARY" ]; then
    BINARY="$ARCH_BINARY"
elif [ -f "$ROOT_BIN" ]; then
    BINARY="$ROOT_BIN"
elif [ -f "$ROOT_ARCH_BIN" ]; then
    BINARY="$ROOT_ARCH_BIN"
else
    echo "Binary $BINARY not found. Building..."
    
    if ! command -v go >/dev/null 2>&1; then
        echo "Error: 'go' is not installed but is required to build the binary."
        echo "Please install Go to proceed."
        exit 1
    fi
    
    if [ ! -d "$ROOT_DIR/vendor" ]; then
        echo "Checking and installing required dependencies..."
        (cd "$ROOT_DIR" && go mod tidy && go mod vendor)
    fi

    if command -v make >/dev/null 2>&1; then
        (cd "$ROOT_DIR" && make build)
        BINARY="$ROOT_DIR/bin/netconfig"
    else
        echo "make is unavailable, building directly with go..."
        VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo dev)
        LDFLAGS="-s -w -X main.version=$VERSION"
        (cd "$ROOT_DIR" && CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags "$LDFLAGS" -o bin/netconfig ./cmd/netconfig)
        BINARY="$ROOT_DIR/bin/netconfig"
    fi
fi

# A subcommand (backup, show-backup) as the first argument is passed through
# untouched. Otherwise this is the classic configuration runner, which falls
# back to commands.txt unless told where its commands come from.
HAS_CMD=0
case "$1" in
    backup|show-backup)
        HAS_CMD=1
        ;;
    *)
        for arg in "$@"; do
            case "$arg" in
                -commands|-commands=*|-template|-template=*|-h|--help|-version)
                    HAS_CMD=1
                    ;;
            esac
        done
        ;;
esac

if [ "$HAS_CMD" -eq 0 ]; then
    set -- "$@" -commands commands.txt
fi

exec "$BINARY" "$@"


