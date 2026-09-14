# Source — Review 3 Prototype

Implements 8 of the 10 designed modules from `docs/chapter3_methodology.md` §3.6: repository ingestion, parsing & chunking, the embedding service, the OWASP/CWE security knowledge base, dual-context retrieval, rule-based severity scoring, a SQLite-backed findings store, and template-based remediation generation. LLM Security Analysis (the "verdict" step) and the Dashboard remain Review 4/5 scope and are not implemented here — see `docs/chapter4_implementation.md` §4.8 for the exact reasoning and honesty framing.

## Setup

```bash
pip install -r ../requirements.txt
```

## Layout

```
rag_vuln_detect/
  ingestion/clone.py         Repository Ingestion module
  chunking/chunker.py        Parsing & Chunking module (tree-sitter)
  embeddings/embedder.py     Embedding Service (+ idf.py weighting)
  vectorstore/faiss_store.py Vector Store wrapper (FAISS)
  knowledge_base/            OWASP Top 10:2025 + CWE Top 25:2025 content, KB builder
  severity/scorer.py         Severity Scoring — rule-based/CVSS-inspired, margin-calibrated confidence
  findings_store/store.py    Findings Store — SQLite (documented MongoDB substitute)
  remediation/generator.py   Remediation Generation — template-based, CWE-keyed
  pipeline/run_pipeline.py   Retrieval-only pipeline (Ingestion -> ... -> Retrieval)
  pipeline/full_scan.py      Extended pipeline: adds Severity Scoring -> Findings Store -> Remediation
tests/                       Automated tests (pytest) — one file per module
```

## Run it

```bash
# Retrieval-only pipeline against a real public repo (defaults to OWASP/NodeGoat)
python -m rag_vuln_detect.pipeline.run_pipeline

# Extended pipeline: also scores severity, persists findings, generates remediation
python -m rag_vuln_detect.pipeline.full_scan

# Or against any other public GitHub repo:
python -m rag_vuln_detect.pipeline.full_scan https://github.com/<owner>/<repo>.git

# Rebuild the security knowledge base index from scratch
python -m rag_vuln_detect.knowledge_base.build_kb

# Run the retrieval-accuracy benchmark (writes to ../results/)
python ../evaluation/run_benchmark.py
python ../evaluation/plot_pipeline_stats.py   # after run_pipeline has produced a report

# Run the test suite (32 tests as of this sprint)
python -m pytest tests/ -v
```

## Candidate findings, not verified vulnerabilities

`full_scan.py`'s output (and everything stored in `findings_store`) is a set of *candidate* findings: each is a code chunk paired with its nearest Security Knowledge Base match, scored as if that match were a true positive. None of this has been confirmed by an LLM reading the actual code — that confirmation step (LLM Security Analysis) is Review 4/5 scope. This mirrors how a traditional SAST tool's raw output is a list of candidates for triage, not a list of confirmed vulnerabilities. See `severity/scorer.py`'s module docstring for the full reasoning.

## Key implementation decision: the embedding model

The proposal/Chapter 3 named a "code-specialised embedding model." This build environment's network policy blocks Hugging Face Hub and Stanford NLP's direct file host — confirmed by direct connection tests, not assumed — which is where such models are normally downloaded from. GitHub-hosted distribution is reachable, so `embeddings/embedder.py` uses IDF-weighted averaged GloVe word vectors (`glove-wiki-gigaword-100`, via `gensim`'s GitHub-hosted `gensim-data`) as a documented, swappable substitute. See that file's module docstring and `docs/chapter4_implementation.md` §4.2 for the full reasoning and the measured retrieval-accuracy numbers this choice produced.
