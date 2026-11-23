@echo off
title WouldApp VPN
cd /d "%~dp0"

:: 1. Primary: Native Electron Desktop Application (No browser, no tabs, system tray)
set "ELECTRON_DIR=%ProgramData%\WouldApp\electron"
set "ELECTRON_SRC=node_modules\electron\dist"

if exist "%ELECTRON_SRC%\electron.exe" (
    if not exist "%ELECTRON_DIR%\electron.exe" (
        robocopy "%ELECTRON_SRC%" "%ELECTRON_DIR%" /E /NFL /NDL /NJH /NJS >nul 2>&1
    )
    if exist "%ELECTRON_DIR%\electron.exe" (
        start "" "%ELECTRON_DIR%\electron.exe" "%~dp0."
        exit
    )
    start "" "%ELECTRON_SRC%\electron.exe" "%~dp0."
    exit
)

:: 2. Fallback: Standalone Node.js server + Chromeless window
set "SAFE_DIR=%ProgramData%\WouldApp\bin"
if not exist "%SAFE_DIR%" mkdir "%SAFE_DIR%" >nul 2>&1

set "NODE_BIN="
if exist "bin\node.exe" (
    if not exist "%SAFE_DIR%\node.exe" copy /y "bin\node.exe" "%SAFE_DIR%\node.exe" >nul 2>&1
    if exist "%SAFE_DIR%\node.exe" (
        set "NODE_BIN=%SAFE_DIR%\node.exe"
    ) else (
        set "NODE_BIN=bin\node.exe"
    )
)
if not defined NODE_BIN (
    where node >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        set "NODE_BIN=node"
    ) else if exist "%SAFE_DIR%\node.exe" (
        set "NODE_BIN=%SAFE_DIR%\node.exe"
    ) else (
        set "NODE_BIN=bin\node.exe"
    )
)

:: Start server in background
start "WouldApp Server" /min "%NODE_BIN%" server.js
timeout /t 2 /nobreak >nul

set "PROFILE=%LOCALAPPDATA%\WouldApp\Profile"
set "APP_FLAGS=--app="http://127.0.0.1:3005" --user-data-dir="%PROFILE%" --no-first-run --no-default-browser-check --disable-features=Translate,OptimizationHints,MediaRouter,msHub,msEdgeSidebarV2,msEdgeFre --disable-extensions --disable-sync --window-size=1120,780 --app-id=WouldAppVPN"

if exist "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe" (
    start "" "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe" %APP_FLAGS%
    exit
)
if exist "%ProgramFiles%\Microsoft\Edge\Application\msedge.exe" (
    start "" "%ProgramFiles%\Microsoft\Edge\Application\msedge.exe" %APP_FLAGS%
    exit
)
if exist "%LOCALAPPDATA%\Microsoft\Edge\Application\msedge.exe" (
    start "" "%LOCALAPPDATA%\Microsoft\Edge\Application\msedge.exe" %APP_FLAGS%
    exit
)
if exist "%ProgramFiles%\Google\Chrome\Application\chrome.exe" (
    start "" "%ProgramFiles%\Google\Chrome\Application\chrome.exe" %APP_FLAGS%
    exit
)
if exist "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" (
    start "" "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" %APP_FLAGS%
    exit
)

start http://127.0.0.1:3005
exit
