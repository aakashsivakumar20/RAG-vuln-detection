#!/usr/bin/env bash
# Fills the verdict cache for the bundled demo app so the live demo scan finishes in seconds.
# Run once, online, with your key in .env, before the review (about 3-6 minutes on a free tier).
set -e
cd "$(dirname "$0")"
PYTHONPATH=src .venv/bin/python -m rag_vuln_detect.pipeline.scan demo/vulnerable_demo_app --max-llm 40
PYTHONPATH=src .venv/bin/python -m rag_vuln_detect.pipeline.scan demo/multilang_demo_app --max-llm 40
echo "Done. 'Scan bundled demo app' now replays these verdicts in seconds."
