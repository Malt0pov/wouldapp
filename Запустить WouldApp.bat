@echo off
title WouldApp VPN
cd /d "%~dp0"

:: 1. Find Node.js (bundled in bin\node.exe or system PATH)
set "NODE_BIN=bin\node.exe"
if not exist "%NODE_BIN%" set "NODE_BIN=node.exe"

:: 2. Start server in background
start "" /b "%NODE_BIN%" server.js
timeout /t 1 /nobreak >nul

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
