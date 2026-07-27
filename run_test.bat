@echo off
setlocal
cd /d "%~dp0"
set "PYTHONHOME="
set "PYTHONPATH="
set "PY_CMD="
if exist ".venv\Scripts\python.exe" set "PY_CMD=.venv\Scripts\python.exe"
if not defined PY_CMD (
  py -3 -c "import sys; assert sys.version_info >= (3, 10)" >nul 2>nul && set "PY_CMD=py -3"
)
if not defined PY_CMD (
  python -c "import sys; assert sys.version_info >= (3, 10)" >nul 2>nul && set "PY_CMD=python"
)
if not defined PY_CMD (
  echo [ERROR] A working Python 3.10-3.12 installation was not found.
  echo Repair or install Python, enable "Add Python to PATH", and retry.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  echo [INFO] Virtual environment not found. Creating .venv...
  %PY_CMD% -m venv .venv
  if errorlevel 1 (
    echo [ERROR] Failed to create .venv.
    pause
    exit /b 1
  )
  echo [INFO] Installing dependencies...
  ".venv\Scripts\python.exe" -m pip install --upgrade pip
  ".venv\Scripts\python.exe" -m pip install -r requirements.txt
  if errorlevel 1 (
    echo [ERROR] Failed to install requirements.
    pause
    exit /b 1
  )
)
echo Running safe NetMask Sentinel traffic test...
echo.
echo Choose mode:
echo   0. mock (recommended for demo on this PC)
echo   1. normal
echo   2. stress
echo   3. scan-like
echo.
set /p MODE_CHOICE=Enter option [0-3, default 0]:
set MODE=mock
if "%MODE_CHOICE%"=="1" set MODE=normal
if "%MODE_CHOICE%"=="2" set MODE=stress
if "%MODE_CHOICE%"=="3" set MODE=scan-like
echo.
set /p TARGET_HOST=Target host [default 127.0.0.1]:
if "%TARGET_HOST%"=="" set TARGET_HOST=127.0.0.1
set /p TARGET_PORT=Target port [default 5000]:
if "%TARGET_PORT%"=="" set TARGET_PORT=5000
".venv\Scripts\python.exe" "safe_traffic_test.py" --mode "%MODE%" --host "%TARGET_HOST%" --port "%TARGET_PORT%"
echo.
echo Test finished. Press any key to close...
pause >nul
endlocal