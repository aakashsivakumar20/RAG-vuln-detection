#!/usr/bin/env bash
cd "$(dirname "$0")"
[ -x .venv/bin/python ] || ./setup.sh
PYTHONPATH=src exec .venv/bin/python -m rag_vuln_detect.api.server "$@"
