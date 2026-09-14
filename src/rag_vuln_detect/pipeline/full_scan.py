"""
Extended end-to-end pipeline for this sprint's additional modules:
Ingestion -> Chunking -> Embedding -> Security KB -> Retrieval -> **Severity
Scoring -> Findings Store -> Remediation Generation**.

This extends run_pipeline.py (which stops at dual-context retrieval) with
the three modules built in this sprint (see docs/chapter4_implementation.md
§4.8 and session-log/SESSION_LOG.md). It does NOT call an LLM anywhere --
the LLM Security Analysis "verdict" step remains Review 4/5 scope.

IMPORTANT -- candidate findings, not verified vulnerabilities:
For each sampled code chunk, this pipeline takes the chunk's single nearest
Security Knowledge Base match (top-1) and scores/stores/remediates it AS IF
it were a true positive. This is explicitly a *candidate* finding -- a
retrieval match, not a confirmed vulnerability -- exactly like a
traditional SAST tool's raw output before triage. See severity/scorer.py's
docstring for the full reasoning, and docs/chapter4_implementation.md for
how this is reported to the panel.

Usage:
    python -m rag_vuln_detect.pipeline.full_scan [repo_url] [--sample N]
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
from rag_vuln_detect.severity.scorer import score_finding
from rag_vuln_detect.findings_store.store import Finding, insert_finding, delete_findings_for_repo, count_by_severity
from rag_vuln_detect.remediation.generator import generate_remediation

_HERE = os.path.dirname(os.path.abspath(__file__))
_RESULTS_DIR = os.path.join(_HERE, "..", "..", "..", "results")
_DB_PATH = os.path.join(_HERE, "..", "..", "..", "data", "findings.db")


def run(repo_url: str, sample_n: int = 8, top_k: int = 3, db_path: str = _DB_PATH) -> dict:
    os.makedirs(_RESULTS_DIR, exist_ok=True)
    t0 = time.time()

    # --- Stages 1-3: Ingestion + Chunking (unchanged from run_pipeline.py) ---
    ingest_report = ingest_repository(repo_url, workdir="/tmp/rag_full_scan_run")
    print(ingest_report.summary())

    all_chunks = []
    for f in ingest_report.files_kept:
        all_chunks.extend(chunk_file(f.abs_path, f.rel_path, f.language))
    print(f"Chunking: {len(ingest_report.files_kept)} files -> {len(all_chunks)} chunks")

    # --- Stage 4: Security KB ---
    kb_index, idf = load_knowledge_base()
    print(f"Loaded security knowledge base: {len(kb_index)} entries")

    # --- Stage 4b: Embedding ---
    chunk_texts = [c.text for c in all_chunks]
    chunk_vectors, embed_seconds = embed_texts(chunk_texts, idf=idf)
    print(f"Embedded {len(all_chunks)} code chunks in {embed_seconds:.2f}s")

    # --- Stage 6 (KB side only): sample chunks, retrieve top-2 KB matches ---
    import random
    random.seed(42)
    sample_indices = random.sample(range(len(all_chunks)), min(sample_n, len(all_chunks)))

    # Clear any prior findings for this repo so re-running the demo doesn't
    # accumulate duplicate rows across runs.
    delete_findings_for_repo(repo_url, db_path=db_path)

    findings_summary = []
    for i in sample_indices:
        chunk = all_chunks[i]
        vec = chunk_vectors[i]
        kb_hits = kb_index.search(vec, top_k=max(top_k, 2))
        if not kb_hits:
            continue
        top1 = kb_hits[0]
        top2 = kb_hits[1] if len(kb_hits) > 1 else None

        # --- Stage 7 (NEW): Severity Scoring ---
        assessment = score_finding(top1, top2)

        # --- Stage 8 (NEW): Remediation Generation ---
        remediation = generate_remediation(assessment.cwe_id)

        # --- Stage 9 (NEW): Findings Store (SQLite, MongoDB substitute) ---
        finding = Finding(
            repo_url=repo_url,
            chunk_id=chunk.chunk_id,
            file_path=chunk.repo_rel_path,
            start_line=chunk.start_line,
            end_line=chunk.end_line,
            chunk_name=chunk.name,
            chunk_kind=chunk.kind,
            cwe_id=assessment.cwe_id,
            owasp_category=assessment.owasp_category,
            severity_band=assessment.final_band,
            severity_score=assessment.final_score,
            margin=assessment.margin,
            low_confidence=assessment.low_confidence,
            rationale=assessment.rationale,
            retrieved_kb_context=[
                {"id": h.get("cwe_id", h.get("code")), "similarity": round(h["similarity"], 4)}
                for h in kb_hits
            ],
        )
        row_id = insert_finding(finding, db_path=db_path)

        findings_summary.append({
            "finding_id": row_id,
            "file_path": chunk.repo_rel_path,
            "chunk_name": chunk.name,
            "lines": f"{chunk.start_line}-{chunk.end_line}",
            "nearest_kb_match": assessment.cwe_id or assessment.owasp_category,
            "severity_band": assessment.final_band,
            "severity_score": assessment.final_score,
            "margin": assessment.margin,
            "low_confidence": assessment.low_confidence,
            "has_remediation_template": remediation is not None,
            "remediation_title": remediation.title if remediation else None,
        })

    total_seconds = time.time() - t0
    severity_breakdown = count_by_severity(repo_url=repo_url, db_path=db_path)

    report = {
        "repo_url": repo_url,
        "timing": {
            "embed_seconds": round(embed_seconds, 2),
            "total_seconds": round(total_seconds, 2),
        },
        "counts": {
            "files_kept": len(ingest_report.files_kept),
            "chunks_produced": len(all_chunks),
            "chunks_scanned_this_run": len(findings_summary),
            "findings_stored": len(findings_summary),
        },
        "severity_breakdown": severity_breakdown,
        "sample_candidate_findings": findings_summary,
        "note": (
            "Every row above is a CANDIDATE finding (nearest Security KB match "
            "for a code chunk, scored by rule-based severity) -- not a "
            "confirmed vulnerability. Confirmation requires the LLM Security "
            "Analysis module, which is Review 4/5 scope. See "
            "docs/chapter4_implementation.md for the full framing."
        ),
    }

    out_path = os.path.join(_RESULTS_DIR, "full_scan_report.json")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nSeverity breakdown: {severity_breakdown}")
    print(f"Full report written to {out_path}")
    print(f"Findings persisted to {db_path}")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("repo_url", nargs="?", default="https://github.com/OWASP/NodeGoat.git")
    parser.add_argument("--sample", type=int, default=8)
    args = parser.parse_args()
    run(args.repo_url, sample_n=args.sample)
