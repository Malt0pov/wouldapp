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

:: Run node server in background
start "" /b node server.js
timeout /t 1 /nobreak >nul

:: Launch Edge in standalone app window
start msedge --app="http://localhost:3005" --window-size=440,920
exit
