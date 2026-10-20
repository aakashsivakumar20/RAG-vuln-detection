@echo off
rem Re-runs the measurements shown on the dashboard "Evaluation" page.
rem   run_evaluation.bat            retrieval benchmark (offline, ~1 minute)
rem   run_evaluation.bat llm        LLM verdict benchmark (needs a free API key, ~15-45 minutes depending on the provider; interrupted runs resume from the cache)
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Run setup.bat first.
  exit /b 1
)
set "PYTHONPATH=%~dp0src"
if /i "%~1"=="llm" (
  ".venv\Scripts\python.exe" evaluation\run_llm_benchmark.py %2 %3 %4 %5
) else (
  ".venv\Scripts\python.exe" -m pip install --only-binary=:all: -q -r requirements-dev.txt
  ".venv\Scripts\python.exe" evaluation\run_retrieval_report.py
)
endlocal
