"""
End-to-end pipeline runner for Review 3: Ingestion -> Chunking -> Embedding
-> Security KB -> Dual-context Retrieval.

This wires together every module built for Review 3 exactly as designed in
docs/chapter3_methodology.md §3.1 (steps 1-6) and §3.2 (architecture
diagram), against a REAL cloned repository. It does not call an LLM and
does not do severity scoring / remediation / dashboard rendering — those are
Review 4/5 scope per the Ch.3 work plan (§3.6) and are intentionally absent.

Usage:
    python -m rag_vuln_detect.pipeline.run_pipeline [repo_url] [--sample N]
"""

from __future__ import annotations

import argparse
import json
import os
import time

from rag_vuln_detect.ingestion.clone import ingest_repository
from rag_vuln_detect.chunking.chunker import chunk_file
from rag_vuln_detect.embeddings.embedder import embed_texts, EMBEDDING_DIM
from rag_vuln_detect.vectorstore.faiss_store import VectorIndex
from rag_vuln_detect.knowledge_base.build_kb import load_knowledge_base

_HERE = os.path.dirname(os.path.abspath(__file__))
_RESULTS_DIR = os.path.join(_HERE, "..", "..", "..", "results")


def run(repo_url: str, sample_n: int = 8, top_k: int = 3) -> dict:
    os.makedirs(_RESULTS_DIR, exist_ok=True)
    t0 = time.time()

    # --- Stage 1-2: Ingestion ---
    ingest_report = ingest_repository(repo_url, workdir="/tmp/rag_pipeline_run")
    print(ingest_report.summary())

    # --- Stage 3: Chunking ---
    t_chunk_start = time.time()
    all_chunks = []
    for f in ingest_report.files_kept:
        all_chunks.extend(chunk_file(f.abs_path, f.rel_path, f.language))
    chunk_seconds = time.time() - t_chunk_start
    print(f"Chunking: {len(ingest_report.files_kept)} files -> {len(all_chunks)} chunks in {chunk_seconds:.2f}s")

    # --- Stage 4: Security KB (load persistent, shared IDF) ---
    kb_index, idf = load_knowledge_base()
    print(f"Loaded security knowledge base: {len(kb_index)} entries")

    # --- Stage 4b: Embedding (repo chunks, using the KB's IDF weights) ---
    chunk_texts = [c.text for c in all_chunks]
    chunk_vectors, embed_seconds = embed_texts(chunk_texts, idf=idf)
    print(f"Embedded {len(all_chunks)} code chunks in {embed_seconds:.2f}s "
          f"({len(all_chunks) / embed_seconds if embed_seconds > 0 else float('inf'):.0f} chunks/sec)")

    # --- Stage 5: Vector Store (per-scan repo code index) ---
    repo_index = VectorIndex(dim=EMBEDDING_DIM)
    repo_index.add(chunk_vectors, [c.to_dict() for c in all_chunks])

    # --- Stage 6: Dual-context retrieval, on a sample of chunks ---
    import random
    random.seed(42)
    sample_indices = random.sample(range(len(all_chunks)), min(sample_n, len(all_chunks)))

    retrieval_results = []
    for i in sample_indices:
        chunk = all_chunks[i]
        vec = chunk_vectors[i]

        repo_hits = [
            h for h in repo_index.search(vec, top_k=top_k + 1)
            if h["chunk_id"] != chunk.chunk_id
        ][:top_k]
        kb_hits = kb_index.search(vec, top_k=top_k)

        retrieval_results.append({
            "query_chunk": {
                "repo_rel_path": chunk.repo_rel_path,
                "name": chunk.name,
                "kind": chunk.kind,
                "lines": f"{chunk.start_line}-{chunk.end_line}",
            },
            "retrieved_repo_context": [
                {"path": h["repo_rel_path"], "name": h["name"], "similarity": round(h["similarity"], 3)}
                for h in repo_hits
            ],
            "retrieved_kb_context": [
                {"id": h.get("cwe_id", h.get("code")), "name": h["name"], "similarity": round(h["similarity"], 3)}
                for h in kb_hits
            ],
        })

    total_seconds = time.time() - t0

    report = {
        "repo_url": repo_url,
        "timing": {
            "clone_seconds": round(ingest_report.clone_seconds, 2),
            "chunk_seconds": round(chunk_seconds, 2),
            "embed_seconds": round(embed_seconds, 2),
            "total_seconds": round(total_seconds, 2),
        },
        "counts": {
            "files_seen": ingest_report.total_files_seen,
            "files_kept": len(ingest_report.files_kept),
            "files_skipped_vendored": ingest_report.files_skipped_vendored,
            "files_skipped_binary_or_nonsource": ingest_report.files_skipped_binary_or_nonsource,
            "files_skipped_too_large": ingest_report.files_skipped_too_large,
            "files_skipped_unsupported_language": ingest_report.files_skipped_unsupported_language,
            "chunks_produced": len(all_chunks),
            "kb_entries": len(kb_index),
        },
        "sample_dual_context_retrievals": retrieval_results,
    }

    out_path = os.path.join(_RESULTS_DIR, "pipeline_run_report.json")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nFull report written to {out_path}")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("repo_url", nargs="?", default="https://github.com/OWASP/NodeGoat.git")
    parser.add_argument("--sample", type=int, default=8)
    args = parser.parse_args()
    run(args.repo_url, sample_n=args.sample)
