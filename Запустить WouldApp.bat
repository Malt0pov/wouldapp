@echo off
title WouldApp VPN
cd /d "%~dp0"

:: Non-ASCII / Cyrillic path protection:
:: Node.js and sing-box can fail if executed from a path with Cyrillic (e.g. C:\Users\Ярослав\...).
:: Mirror runtime node.exe to %ProgramData%\WouldApp\bin\node.exe (guaranteed 100% ASCII path on any Windows PC).
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

:: Start server in background (independent process)
start "WouldApp Server" /min "%NODE_BIN%" server.js
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
