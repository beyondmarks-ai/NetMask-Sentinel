@echo off
setlocal EnableExtensions DisableDelayedExpansion
title NetMask Sentinel - Authorized Alert Test
color 0B

echo ============================================================
echo        NetMask Sentinel - Authorized Two-PC Test
echo ============================================================
echo.
echo This sends one token-protected test notification to a NetMask
echo sensor on your private network. It does not exploit the computer.
echo.
if not defined NMS_TARGET set /p "NMS_TARGET=Sensor PC private IPv4 address (example 192.168.1.2): "
if not defined NMS_TARGET goto :missing_target

echo.
echo On the sensor PC, double-click Show-LabAlertToken.ps1 and copy
echo the token it displays.
if not defined NMS_TOKEN set /p "NMS_TOKEN=Paste the lab alert token: "
if not defined NMS_TOKEN goto :missing_token

echo.
if not defined NMS_CONFIRM set /p "NMS_CONFIRM=Type AUTHORIZED to confirm you have permission: "
if /I not "%NMS_CONFIRM%"=="AUTHORIZED" goto :not_authorized

echo.
echo Contacting http://%NMS_TARGET%:5000 ...
set "NMS_EXIT_CODE=1"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference = 'Stop';" ^
  "$target = $env:NMS_TARGET.Trim();" ^
  "$parsed = $null;" ^
  "if (-not [System.Net.IPAddress]::TryParse($target, [ref]$parsed) -or $parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { throw 'Enter a valid IPv4 address, for example 192.168.1.2.' };" ^
  "$bytes = $parsed.GetAddressBytes();" ^
  "$private = ($bytes[0] -eq 10) -or ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or ($bytes[0] -eq 127) -or ($bytes[0] -eq 169 -and $bytes[1] -eq 254);" ^
  "if (-not $private) { throw 'For safety, this tester only accepts private-network IPv4 addresses.' };" ^
  "$uri = 'http://' + $target + ':5000/api/lab-alert';" ^
  "$reply = Invoke-RestMethod -Method Post -Uri $uri -Headers @{'X-NetMask-Lab-Token'=$env:NMS_TOKEN} -TimeoutSec 15;" ^
  "if (-not $reply.success) { throw 'The sensor did not accept the test.' };" ^
  "Write-Host ''; Write-Host 'SUCCESS: The alert was accepted.' -ForegroundColor Green;" ^
  "Write-Host ('Observed tester IP: ' + $reply.source_ip) -ForegroundColor Cyan;" ^
  "Write-Host 'Check Recent Incidents on the local and online dashboards.';" ^
  "exit 0"
set "NMS_EXIT_CODE=%ERRORLEVEL%"

if "%NMS_EXIT_CODE%"=="0" goto :done
echo.
echo TEST FAILED.
echo Make sure NetMask is running, both PCs are on the same private network,
echo Windows Firewall allows port 5000 on Private networks, and the token is exact.
goto :done

:missing_target
echo.
echo No sensor IP was entered. Nothing was sent.
goto :done

:missing_token
echo.
echo No lab token was entered. Nothing was sent.
goto :done

:not_authorized
echo.
echo Authorization was not confirmed. Nothing was sent.

:done
echo.
if not defined NMS_NO_PAUSE pause
endlocal & exit /b %NMS_EXIT_CODE%
