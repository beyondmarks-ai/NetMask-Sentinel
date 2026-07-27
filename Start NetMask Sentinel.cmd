@echo off
cd /d "%~dp0"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-NetMask.ps1"
if errorlevel 1 (
  echo.
  echo NetMask Sentinel could not start. See the message above.
  pause
)