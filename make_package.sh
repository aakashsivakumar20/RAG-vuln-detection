#!/usr/bin/env bash
# Build the distributable zip:  ./make_package.sh [output.zip]
set -e
cd "$(dirname "$0")"
OUT="${1:-../rag-vuln-detect-project.zip}"
rm -f "$OUT"
cd ..
zip -qr "$OUT" "$(basename "$OLDPWD")" \
  -x '*/.git/*' '*/node_modules/*' '*/__pycache__/*' '*/.pytest_cache/*' '*/.venv/*' '*/.env' \
     '*/data/llm_cache.jsonl' '*/data/findings.db*' '*/data/cache/*' '*.pyc' '*/make_package.sh'
echo "wrote $OUT"
