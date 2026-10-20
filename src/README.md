# Source

All ten modules of the Chapter 3 design are implemented here; see the project `README.md` for the module table,
quick start and measured results.

```
rag_vuln_detect/
  ingestion/       repository intake (git / GitHub zip / folder / .zip)
  chunking/        tree-sitter function/class units
  embeddings/      GloVe (numpy loader) + IDF-weighted averaging
  vectorstore/     FAISS wrapper
  knowledge_base/  OWASP Top 10:2025 + CWE Top 25:2025 entries, lexical indicators, KB builder
  retrieval/       hybrid dense + BM25 retriever
  llm/             providers (Groq / Gemini / OpenAI-compatible), prompts + rubrics, verdict parsing, cache
  severity/        rule-based CVSS-banded scoring (LLM verdict path + retrieval-only fallback)
  remediation/     deterministic CWE fix templates (LLM fixes come from llm/)
  findings_store/  SQLite store (scans + findings, migration, triage)
  pipeline/        scan.py (full pipeline, CLI); run_pipeline.py / full_scan.py (earlier prototype entry points)
  api/             stdlib HTTP API + dashboard host + exporters (JSON / CSV / SARIF)
tests/             automated tests (run: python -m pytest -q src/tests)
```

Run from the project root with `PYTHONPATH=src` (the `.bat`/`.sh` scripts do this):

```
python -m rag_vuln_detect.api.server                      # dashboard + API
python -m rag_vuln_detect.pipeline.scan <folder|zip|url>  # terminal scan
```
