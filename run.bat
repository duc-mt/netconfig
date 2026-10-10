@echo off
rem ==============================================================================
rem Script Name:   run.bat
rem Description:   Universal launcher for NetConfig on Windows (amd64 binary).
rem Author:        Mai Tan Duc <ducmai.network@gmail.com>
rem Created:       2026-10-10
rem Version:       1.0.0
rem License:       MIT
rem ==============================================================================
rem Usage:         run.bat
rem ==============================================================================

set BINARY="%~dp0bin\netconfig-windows-amd64.exe"
if exist %BINARY% goto :run

echo Binary %BINARY% not found. Building...

REM Check if Go is installed
where go >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Error: 'go' is not installed but is required to build the binary.
    echo Please install Go to proceed.
    exit /b 1
)

echo Checking and installing required dependencies...
go mod tidy
go mod vendor

echo Building binary...
set VERSION=dev
for /f "delims=" %%i in ('git describe --tags --always --dirty 2^>nul') do set VERSION=%%i
set LDFLAGS=-s -w -X main.version=%VERSION%

set CGO_ENABLED=0
go build -mod=vendor -trimpath -ldflags "%LDFLAGS%" -o "%~dp0bin\netconfig.exe" .\cmd\netconfig
set BINARY="%~dp0bin\netconfig.exe"

:run
%BINARY% %*
