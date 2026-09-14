# Source — Review 3 Prototype

Implements the Review 3 scope from `docs/chapter3_methodology.md` §3.6: repository ingestion, parsing & chunking, the embedding service, the OWASP/CWE security knowledge base, and dual-context retrieval. LLM analysis, severity scoring, remediation generation, and the dashboard are Review 4/5 scope and are not implemented here.

## Setup

```bash
pip install -r ../requirements.txt
```

## Layout

```
rag_vuln_detect/
  ingestion/clone.py        Repository Ingestion module
  chunking/chunker.py       Parsing & Chunking module (tree-sitter)
  embeddings/embedder.py    Embedding Service (+ idf.py weighting)
  vectorstore/faiss_store.py  Vector Store wrapper (FAISS)
  knowledge_base/           OWASP Top 10:2025 + CWE Top 25:2025 content, KB builder
  pipeline/run_pipeline.py  Wires all of the above together end-to-end
tests/test_pipeline.py      Automated tests (pytest)
```

## Run it

```bash
# Full pipeline against a real public repo (defaults to OWASP/NodeGoat)
python -m rag_vuln_detect.pipeline.run_pipeline

# Or against any other public GitHub repo:
python -m rag_vuln_detect.pipeline.run_pipeline https://github.com/<owner>/<repo>.git

# Rebuild the security knowledge base index from scratch
python -m rag_vuln_detect.knowledge_base.build_kb

# Run the retrieval-accuracy benchmark (writes to ../results/)
python ../evaluation/run_benchmark.py
python ../evaluation/plot_pipeline_stats.py   # after run_pipeline has produced a report

# Run the test suite
python -m pytest tests/ -v
```

## Key implementation decision: the embedding model

The proposal/Chapter 3 named a "code-specialised embedding model." This build environment's network policy blocks Hugging Face Hub and Stanford NLP's direct file host — confirmed by direct connection tests, not assumed — which is where such models are normally downloaded from. GitHub-hosted distribution is reachable, so `embeddings/embedder.py` uses IDF-weighted averaged GloVe word vectors (`glove-wiki-gigaword-100`, via `gensim`'s GitHub-hosted `gensim-data`) as a documented, swappable substitute. See that file's module docstring and `docs/chapter4_implementation.md` §4.2 for the full reasoning and the measured retrieval-accuracy numbers this choice produced.
