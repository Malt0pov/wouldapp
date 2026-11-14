@echo off
title WouldApp VPN
cd /d "%~dp0"

:: Check for Administrator permissions
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [WouldApp] Запрос прав администратора для Wintun адаптера...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

:: Find node executable (bundled in bin\node.exe or system PATH)
set "NODE_BIN=bin\node.exe"
if not exist "%NODE_BIN%" set "NODE_BIN=node.exe"

:: Run node server in background
start "" /b "%NODE_BIN%" server.js
timeout /t 1 /nobreak >nul

:: Launch Edge in standalone desktop app window
start msedge --app="http://localhost:3005" --window-size=980,720
exit
