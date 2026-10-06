@echo off
setlocal
cd /d "%~dp0"
set "PYTHONHOME="
set "PYTHONPATH="
set "USE_EXE=0"
if exist "%~dp0NetMask-Lab-Test\NetMask-Lab-Test.exe" set "USE_EXE=1"
if "%USE_EXE%"=="0" (
  set "PYTHON_CMD="
  py -3 -c "import sys; assert sys.version_info >= (3, 10)" >nul 2>nul && set "PYTHON_CMD=py -3"
  if not defined PYTHON_CMD (
    python -c "import sys; assert sys.version_info >= (3, 10)" >nul 2>nul && set "PYTHON_CMD=python"
  )
  if not defined PYTHON_CMD (
    echo NetMask-Lab-Test.exe is missing and no working Python was found.
    echo Extract every file from NetMask-Remote-Lab-Test.zip and retry.
    pause
    exit /b 1
  )
)
echo NetMask Sentinel - Authorized Private-Network Test
echo This sends bounded connections and normal HTTP requests only.
echo.
set /p TARGET=Enter the private IP of the NetMask computer:
if "%TARGET%"=="" (
  echo A target is required.
  pause
  exit /b 1
)
echo.
echo Profiles:
echo   1. baseline  - ordinary low-rate validation
echo   2. burst     - bounded traffic spike
echo   3. discovery - bounded private port connection pattern
echo   4. alert     - guaranteed authorized dashboard notification; no attack payload
set /p CHOICE=Choose [1-4, default 1]:
set MODE=baseline
if "%CHOICE%"=="2" set MODE=burst
if "%CHOICE%"=="3" set MODE=discovery
if "%CHOICE%"=="4" set MODE=alert
echo.
set /p CONFIRM=Type AUTHORIZED to confirm you have permission:
if /I not "%CONFIRM%"=="AUTHORIZED" (
  echo Authorization was not confirmed. Nothing was sent.
  pause
  exit /b 2
)
if "%MODE%"=="alert" (
  echo On the NetMask computer run Show-LabAlertToken.ps1 and enter its token below.
  set /p LAB_TOKEN=Lab alert token:
  if "%LAB_TOKEN%"=="" (
    echo A lab alert token is required.
    pause
    exit /b 2
  )
)
if "%USE_EXE%"=="1" (
  "%~dp0NetMask-Lab-Test\NetMask-Lab-Test.exe" --target "%TARGET%" --port 5000 --mode "%MODE%" --lab-token "%LAB_TOKEN%" --authorized-lab-use
) else (
  %PYTHON_CMD% "%~dp0netmask_lab_traffic.py" --target "%TARGET%" --port 5000 --mode "%MODE%" --lab-token "%LAB_TOKEN%" --authorized-lab-use
)
echo.
pause
endlocal
