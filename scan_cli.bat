@echo off
rem Command-line scan:  scan_cli.bat <folder | .zip | git-url> [--max-llm 40] [--no-llm] [--no-rag]
rem With no argument the bundled demo application is scanned.
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Run setup.bat first.
  exit /b 1
)
set "PYTHONPATH=%~dp0src"
set "FIRST=%~1"
if "%~1"=="" (
  ".venv\Scripts\python.exe" -m rag_vuln_detect.pipeline.scan "%~dp0demo\vulnerable_demo_app"
) else if "%FIRST:~0,1%"=="-" (
  ".venv\Scripts\python.exe" -m rag_vuln_detect.pipeline.scan "%~dp0demo\vulnerable_demo_app" %*
) else (
  ".venv\Scripts\python.exe" -m rag_vuln_detect.pipeline.scan %*
)
endlocal
