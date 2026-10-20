@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Run setup.bat first.
  exit /b 1
)
".venv\Scripts\python.exe" -m pip install --only-binary=:all: -q -r requirements-dev.txt
set "PYTHONPATH=%~dp0src"
".venv\Scripts\python.exe" -m pytest -q src\tests
endlocal
