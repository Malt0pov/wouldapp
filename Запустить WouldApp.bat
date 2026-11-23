@echo off
title WouldApp VPN
cd /d "%~dp0"

:: 1. Find Node.js (prefer system node, fallback to bundled bin\node.exe)
set "NODE_BIN=node"
where node >nul 2>nul
if %ERRORLEVEL% neq 0 (
    if exist "bin\node.exe" set "NODE_BIN=bin\node.exe"
)

:: 2. Start server in minimized window (independent process that stays alive after bat exits)
start "WouldApp Server" /min %NODE_BIN% server.js
timeout /t 2 /nobreak >nul

:: 3. Launch isolated chromeless application window
set "PROFILE=%LOCALAPPDATA%\WouldApp\Profile"
set "APP_FLAGS=--app="http://127.0.0.1:3005" --user-data-dir="%PROFILE%" --no-first-run --no-default-browser-check --disable-features=Translate,OptimizationHints,MediaRouter,msHub,msEdgeSidebarV2,msEdgeFre --disable-extensions --disable-sync --window-size=1120,780 --app-id=WouldAppVPN"

:: Search Edge
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

:: Search Chrome
if exist "%ProgramFiles%\Google\Chrome\Application\chrome.exe" (
    start "" "%ProgramFiles%\Google\Chrome\Application\chrome.exe" %APP_FLAGS%
    exit
)
if exist "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" (
    start "" "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" %APP_FLAGS%
    exit
)

:: Fallback to default browser
start http://127.0.0.1:3005
exit
