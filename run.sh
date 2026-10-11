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

BINARY="bin/netconfig-${OS}-${ARCH}"
if [ "$OS" = "windows" ]; then
    BINARY="${BINARY}.exe"
fi

if [ ! -f "$BINARY" ]; then
    echo "Binary $BINARY not found. Building..."
    
    if ! command -v go >/dev/null 2>&1; then
        echo "Error: 'go' is not installed but is required to build the binary."
        echo "Please install Go to proceed."
        exit 1
    fi
    
    echo "Checking and installing required dependencies..."
    go mod tidy
    go mod vendor

    if command -v make >/dev/null 2>&1; then
        make build
        BINARY="bin/netconfig"
    else
        echo "make is unavailable, building directly with go..."
        VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo dev)
        LDFLAGS="-s -w -X main.version=$VERSION"
        CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags "$LDFLAGS" -o bin/netconfig ./cmd/netconfig
        BINARY="bin/netconfig"
    fi
fi

HAS_CMD=0
for arg in "$@"; do
    case "$arg" in
        -commands|-commands=*|-template|-template=*|-h|--help|-version)
            HAS_CMD=1
            ;;
    esac
done

if [ "$HAS_CMD" -eq 0 ]; then
    set -- "$@" -commands commands.txt
fi

exec "$BINARY" "$@"


