@echo off
setlocal
cd /d "%~dp0"
echo ============================================================
echo  RAG Vulnerability Scanner - one-time setup
echo ============================================================

rem --- find a supported Python (3.10 - 3.14) by asking each one for its minor version ---
set "PYCMD="
for %%M in (13 12 11 14 10) do call :try %%M
if not defined PYCMD (
  for /f "delims=" %%A in ('python -c "import sys;print(sys.version_info[0]*100+sys.version_info[1])" 2^>nul') do (
    if "%%A" GEQ "310" if "%%A" LEQ "314" set "PYCMD=python"
  )
)
if not defined PYCMD (
  echo.
  echo ERROR: no Python 3.10 - 3.14 found. Install one from https://www.python.org/downloads/
  echo        and tick "Add python.exe to PATH", then run setup.bat again.
  exit /b 1
)
echo Using: %PYCMD%

if exist ".venv\Scripts\python.exe" goto have_venv
echo Creating virtual environment .venv ...
%PYCMD% -m venv .venv
if not exist ".venv\Scripts\python.exe" (
  echo ERROR: could not create the virtual environment with %PYCMD%.
  exit /b 1
)
:have_venv

echo Installing packages (pre-built wheels only; no compiler needed) ...
".venv\Scripts\python.exe" -m pip install --upgrade pip --quiet
".venv\Scripts\python.exe" -m pip install --only-binary=:all: -r requirements.txt
if errorlevel 1 (
  echo.
  echo ERROR: package installation failed. Check your internet connection and run setup.bat again.
  echo        If it keeps failing, send the lines above to your project partner.
  exit /b 1
)

if not exist ".env" copy ".env.example" ".env" >nul

echo.
echo Running self-check ...
set "PYTHONPATH=%~dp0src"
".venv\Scripts\python.exe" check_setup.py
if errorlevel 1 exit /b 1

echo.
echo Setup finished. Next:
echo   1. (optional but recommended) get a FREE key: https://console.groq.com/keys
echo      or https://aistudio.google.com/apikey and paste it in the dashboard under Settings.
echo   2. double-click run.bat to start the dashboard.
exit /b 0

:try
if defined PYCMD goto :eof
for /f "delims=" %%A in ('py -3.%1 -c "import sys;print(sys.version_info[1])" 2^>nul') do (
  if "%%A"=="%1" set "PYCMD=py -3.%1"
)
goto :eof
