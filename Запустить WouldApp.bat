@echo off
title WouldApp VPN
cd /d "%~dp0"
start "" /b node server.js
timeout /t 1 /nobreak >nul
start msedge --app="http://localhost:3005" --window-size=440,920
exit
