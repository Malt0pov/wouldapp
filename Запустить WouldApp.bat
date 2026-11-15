@echo off
title WouldApp VPN
cd /d "%~dp0"

:: Find node executable (bundled in bin\node.exe or system PATH)
set "NODE_BIN=bin\node.exe"
if not exist "%NODE_BIN%" set "NODE_BIN=node.exe"

:: Run node server in background without elevation prompts
start "" /b "%NODE_BIN%" server.js
timeout /t 1 /nobreak >nul

:: Launch Edge in standalone desktop app window
start msedge --app="http://localhost:3005" --window-size=1080,750
exit
