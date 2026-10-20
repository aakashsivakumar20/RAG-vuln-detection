#!/usr/bin/env bash
# One-time setup for Linux / macOS:  ./setup.sh
set -e
cd "$(dirname "$0")"
PY=""
for v in 3.13 3.12 3.11 3.14 3.10; do
  if command -v "python$v" >/dev/null 2>&1; then PY="python$v"; break; fi
done
[ -z "$PY" ] && command -v python3 >/dev/null 2>&1 && PY=python3
[ -z "$PY" ] && { echo "Python 3.10-3.14 not found"; exit 1; }
echo "Using $($PY --version)"
[ -d .venv ] || "$PY" -m venv .venv
.venv/bin/python -m pip install --upgrade pip -q
.venv/bin/python -m pip install --only-binary=:all: -r requirements.txt
[ -f .env ] || cp .env.example .env
PYTHONPATH=src .venv/bin/python check_setup.py
echo "Done. Start the dashboard with ./run.sh"
