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
# Universal launcher for netops: auto-detects OS & architecture and executes the appropriate binary.

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

BINARY="$ROOT_DIR/bin/netops"
[ "$OS" = "windows" ] && BINARY="$ROOT_DIR/bin/netops.exe"

ARCH_BINARY="$ROOT_DIR/bin/netops-${OS}-${ARCH}"
[ "$OS" = "windows" ] && ARCH_BINARY="${ARCH_BINARY}.exe"

ROOT_BIN="$ROOT_DIR/netops"
[ "$OS" = "windows" ] && ROOT_BIN="$ROOT_DIR/netops.exe"

ROOT_ARCH_BIN="$ROOT_DIR/netops-${OS}-${ARCH}"
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
        BINARY="$ROOT_DIR/bin/netops"
    else
        echo "make is unavailable, building directly with go..."
        VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo dev)
        LDFLAGS="-s -w -X main.version=$VERSION"
        (cd "$ROOT_DIR" && CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags "$LDFLAGS" -o bin/netops ./cmd/netops)
        BINARY="$ROOT_DIR/bin/netops"
    fi
fi

# A subcommand is strictly required. For the "apply" subcommand, default to
# -commands commands.txt unless explicit commands/template or help flags are given.
case "$1" in
    apply)
        HAS_CMDS_FLAG=0
        for arg in "$@"; do
            case "$arg" in
                -commands|-commands=*|-template|-template=*|-h|--help|-version)
                    HAS_CMDS_FLAG=1
                    ;;
            esac
        done
        if [ "$HAS_CMDS_FLAG" -eq 0 ]; then
            set -- "$@" -commands commands.txt
        fi
        ;;
esac

exec "$BINARY" "$@"


