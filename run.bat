@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Not set up yet - running setup.bat first ...
  call setup.bat
  if errorlevel 1 exit /b 1
)
set "PYTHONPATH=%~dp0src"
echo Starting the dashboard - a browser tab opens automatically. Press Ctrl+C here to stop.
".venv\Scripts\python.exe" -m rag_vuln_detect.api.server %*
endlocal
