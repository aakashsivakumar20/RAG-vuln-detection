@echo off
rem Fills the verdict cache for the bundled demo app, so the live demo scan finishes in seconds.
rem Run this ONCE, with internet and your key in .env, before the review (about 6-10 minutes on a free tier for both demos).
rem Do not run it at the same time as run_evaluation.bat llm (they share the same free-tier request limit).
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Run setup.bat first.
  exit /b 1
)
set "PYTHONPATH=%~dp0src"
echo Warming the demo cache (this calls your LLM once per demo function) ...
".venv\Scripts\python.exe" -m rag_vuln_detect.pipeline.scan "%~dp0demo\vulnerable_demo_app" --max-llm 40
echo.
echo Warming the multi-language demo ...
".venv\Scripts\python.exe" -m rag_vuln_detect.pipeline.scan "%~dp0demo\multilang_demo_app" --max-llm 40
echo.
echo Finished. Check the line "LLM calls: N   cache hits: M   errors: 0" above - errors must be 0.
echo In the dashboard, "Scan bundled demo app" now replays these verdicts in seconds.
endlocal
