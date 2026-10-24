@echo off
rem ==============================================================================
rem Script Name:   run.bat
rem Description:   Universal launcher for NetConfig on Windows (amd64 binary).
rem Author:        Mai Tan Duc <ducmai.network@gmail.com>
rem Created:       2026-10-10
rem Version:       1.0.0
rem License:       MIT
rem ==============================================================================
rem Usage:         run.bat [options]   |   run.bat backup [options]   |   run.bat backup show [options]
rem Notes:         every argument, including a leading subcommand, is passed to the binary as is
rem ==============================================================================

set "SCRIPT_DIR=%~dp0"
set "ROOT_DIR=%SCRIPT_DIR%..\"

set BINARY="%ROOT_DIR%bin\netconfig.exe"
set ARCH_BINARY="%ROOT_DIR%bin\netconfig-windows-amd64.exe"
set ROOT_BINARY="%ROOT_DIR%netconfig.exe"
set ROOT_ARCH_BINARY="%ROOT_DIR%netconfig-windows-amd64.exe"

if exist %BINARY% goto :run
if exist %ARCH_BINARY% (
    set BINARY=%ARCH_BINARY%
    goto :run
)
if exist %ROOT_BINARY% (
    set BINARY=%ROOT_BINARY%
    goto :run
)
if exist %ROOT_ARCH_BINARY% (
    set BINARY=%ROOT_ARCH_BINARY%
    goto :run
)

echo Binary %BINARY% not found. Building...

REM Check if Go is installed
where go >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Error: 'go' is not installed but is required to build the binary.
    echo Please install Go to proceed.
    exit /b 1
)

pushd "%ROOT_DIR%"

if not exist "%ROOT_DIR%vendor" (
    echo Vendor directory not found. Downloading dependencies...
    go mod tidy
    go mod vendor
)

echo Building binary...
set VERSION=dev
for /f "delims=" %%i in ('git describe --tags --always --dirty 2^>nul') do set VERSION=%%i
set LDFLAGS=-s -w -X main.version=%VERSION%

set CGO_ENABLED=0
go build -mod=vendor -trimpath -ldflags "%LDFLAGS%" -o "%ROOT_DIR%bin\netconfig.exe" .\cmd\netconfig
popd
set BINARY="%ROOT_DIR%bin\netconfig.exe"

:run
%BINARY% %*
