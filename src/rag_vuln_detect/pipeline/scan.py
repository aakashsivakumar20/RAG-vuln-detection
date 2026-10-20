"""
End-to-end scan pipeline (all ten modules of the Chapter 3 architecture).

    Ingestion -> Chunking -> Embedding -> Vector stores (repo index + security KB)
      -> Hybrid dual-context retrieval -> LLM Security Analysis (verdict)
      -> Severity scoring -> Remediation generation -> Findings store -> (API/dashboard)

What a scan does
  1. Fetch the project (git URL, GitHub URL, .zip or local folder) and pre-filter it.
  2. Split source into function/class units with tree-sitter.
  3. Embed every unit once; build the per-scan repository index (FAISS).
  4. For every unit retrieve the best-matching OWASP/CWE knowledge-base entries (hybrid dense +
     BM25) and rank units by how strongly they resemble a known weakness class.
  5. Send the top-ranked units (budget `max_llm_chunks`, sized for free-tier LLM quotas) to the
     LLM together with the retrieved standards text, CWE rubrics and similar code from the same
     repository; the LLM returns a structured verdict.
  6. Score severity (rule-based, CVSS-inspired, using the LLM verdict + confidence), attach a
     remediation (template and/or LLM-proposed fix, shown as before/after, never auto-applied)
     and store every outcome -- including findings the LLM REJECTED, so false-positive
     filtering stays visible and measurable.

Honest degradation: with no LLM key (or when the provider keeps failing) the same pipeline still
runs, but findings are stored with status "unverified" -- retrieval candidates, explicitly not
claimed to be vulnerabilities.

CLI:
    python -m rag_vuln_detect.pipeline.scan <path-or-url> [--max-llm 40] [--no-llm] [--no-rag]
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import re
import tempfile
import time
import traceback

from rag_vuln_detect.chunking.chunker import chunk_file
from rag_vuln_detect.embeddings.embedder import EMBEDDING_DIM, embed_texts
from rag_vuln_detect.findings_store import store
from rag_vuln_detect.ingestion.clone import ingest_repository
from rag_vuln_detect.knowledge_base.build_kb import load_knowledge_base
from rag_vuln_detect.llm.analyzer import SecurityAnalyzer, Verdict
from rag_vuln_detect.llm.pool import DaemonPool
from rag_vuln_detect.llm.providers import LLMAuthError, LLMError, make_provider
from rag_vuln_detect.remediation.generator import generate_remediation
from rag_vuln_detect.retrieval.patterns import LANG_TAG
from rag_vuln_detect.retrieval.hybrid import HybridRetriever, record_id
from rag_vuln_detect.severity.scorer import score_finding, score_verdict
from rag_vuln_detect.vectorstore.faiss_store import VectorIndex

_TEST_PATH_RE = re.compile(r"(^|/)(tests?|__tests__|spec|specs|e2e|fixtures?|mocks?)(/|$)|(\.|_)(test|spec)\.[jt]sx?$|(^|/)test_[^/]*\.py$|_test\.(py|go|rs|rb|cc|cpp|c)$|_spec\.rb$|Tests?\.(java|kt|cs|php)$", re.I)
MAX_CODE_STORED = 8000
CONSECUTIVE_ERROR_LIMIT = 5


class ScanCancelled(Exception):
    pass


@dataclasses.dataclass
class ScanConfig:
    max_llm_chunks: int = 40          # LLM budget per scan (free tiers allow roughly 30 requests/min)
    kb_top_k: int = 6                 # knowledge-base entries shown to the LLM
    repo_context_k: int = 2           # similar chunks from the same repository shown to the LLM
    use_rag: bool = True              # False = LLM-only ablation (no retrieved context in the prompt)
    skip_tests: bool = True           # do not analyse test/spec/fixture files
    min_chunk_lines: int = 3          # ignore trivial units (one-line getters, re-exports)
    max_candidates_no_llm: int = 25   # unverified candidates stored when no LLM is available
    max_chunks: int = 5000            # safety cap on units per scan
    llm_mode: str = "auto"            # auto | live | replay  (see llm/analyzer.py)
    llm_workers: int = 4              # concurrent LLM requests; the provider's rate limiter still caps requests/minute


def _noop(*_a, **_k):
    return None


def _clip(text: str, n: int) -> str:
    return text if len(text) <= n else text[:n] + "\n... [truncated]"


def _kb_context(hits: list[dict]) -> list[dict]:
    return [{"id": record_id(h), "name": h.get("name", ""), "similarity": h["similarity"],
             "dense": h.get("dense_similarity"), "lexical": h.get("lexical_score"), "pattern": h.get("pattern_score")} for h in hits]


_TEMPLATE_LANGS = {"python", "javascript", "typescript"}


def _template_dict(cwe_id: str | None, language: str | None = None):
    rem = generate_remediation(cwe_id, language)
    if not rem:
        return None
    d = dataclasses.asdict(rem)
    want = LANG_TAG.get((language or "").lower()) if language else None
    if want and rem.language != want:
        d["note"] = (f"There is no standard example for this fix in {language} yet, so the {rem.language.upper()} version "
                     f"of the same idea is shown. The LLM tab has a fix written for your actual code.")
    return d


def run_scan(
    source: str,
    config: ScanConfig | None = None,
    *,
    analyzer: SecurityAnalyzer | None = None,
    db_path: str | None = None,
    workdir: str | None = None,
    progress=None,
    should_cancel=None,
    scan_id: int | None = None,
) -> dict:
    """Run one full scan and return its summary. All state is persisted to the findings store.

    progress(stage, fraction, message) is called as the scan advances; should_cancel() -> bool is
    polled between units. `scan_id` lets a caller (the API) create the scan row first so the
    dashboard can show it immediately.
    """
    cfg = config or ScanConfig()
    progress = progress or _noop
    should_cancel = should_cancel or (lambda: False)
    db = db_path or store._DEFAULT_DB_PATH
    if analyzer is None:
        analyzer = SecurityAnalyzer(make_provider(), mode=cfg.llm_mode)
    llm_ok = analyzer.available
    mode = ("llm-rag" if cfg.use_rag else "llm-only") if llm_ok else "retrieval-only"
    provider_name = analyzer.provider.name if analyzer.provider else ("cache" if llm_ok else "")
    try:
        model_name = analyzer.provider.model if analyzer.provider else ""
    except LLMError:
        model_name = ""

    if scan_id is None:
        scan_id = store.create_scan(source, mode=mode, provider=provider_name, model=model_name,
                                    params=dataclasses.asdict(cfg), db_path=db)
    else:
        store.update_scan(scan_id, db_path=db, mode=mode, provider=provider_name, model=model_name,
                          params=dataclasses.asdict(cfg))

    t_start = time.time()
    timings: dict[str, float] = {}
    counts: dict[str, int] = {}

    def stage(name: str, frac: float, msg: str = ""):
        store.update_scan(scan_id, db_path=db, stage=name, progress=round(frac, 3))
        progress(name, frac, msg)
        if should_cancel():
            raise ScanCancelled()

    pool = None
    abort = {"reason": ""}
    own_workdir = workdir is None
    workdir = workdir or tempfile.mkdtemp(prefix="ragvuln_scan_")
    try:
        # ---- 1. ingestion -------------------------------------------------------------
        stage("ingestion", 0.02, "Fetching and filtering the project")
        t = time.time()
        report = ingest_repository(source, workdir)
        timings["ingestion_s"] = round(time.time() - t, 2)
        counts.update(files_seen=report.total_files_seen, files_analysable=len(report.files_kept),
                      files_skipped_vendored=report.files_skipped_vendored,
                      files_skipped_binary=report.files_skipped_binary_or_nonsource,
                      files_skipped_large=report.files_skipped_too_large,
                      files_skipped_other_language=report.files_skipped_unsupported_language)

        # ---- 2. chunking --------------------------------------------------------------
        stage("chunking", 0.10, f"Parsing {len(report.files_kept)} files")
        t = time.time()
        chunks = []
        skipped_tests = 0
        for f in report.files_kept:
            if cfg.skip_tests and _TEST_PATH_RE.search(f.rel_path.replace("\\", "/")):
                skipped_tests += 1
                continue
            chunks.extend(chunk_file(f.abs_path, f.rel_path.replace("\\", "/"), f.language))
            if len(chunks) >= cfg.max_chunks:
                break
        counts["files_skipped_tests"] = skipped_tests
        counts["chunks_total"] = len(chunks)
        trivial = [c for c in chunks if (c.end_line - c.start_line + 1) < cfg.min_chunk_lines]
        counts["chunks_trivial_skipped"] = len(trivial)
        trivial_ids = {c.chunk_id for c in trivial}
        chunks = [c for c in chunks if c.chunk_id not in trivial_ids]
        timings["chunking_s"] = round(time.time() - t, 2)
        if not chunks:
            raise RuntimeError("no analysable source code found (supported: .py .js .jsx .ts .tsx)")

        # ---- 3. embeddings + repository index ----------------------------------------
        stage("embedding", 0.16, f"Embedding {len(chunks)} code units")
        kb_index, idf = load_knowledge_base()
        retriever = HybridRetriever(kb_index, idf)
        kb_lookup = {r.get("cwe_id"): r.get("owasp_category") for r in retriever.records if r.get("cwe_id")}
        vectors, embed_s = embed_texts([c.text for c in chunks], idf=idf)
        repo_index = VectorIndex(dim=EMBEDDING_DIM)
        repo_index.add(vectors, [c.to_dict() for c in chunks])
        timings["embedding_s"] = round(embed_s, 2)

        # ---- 4. retrieval + prioritisation -------------------------------------------
        stage("retrieval", 0.24, "Matching code against the OWASP / CWE knowledge base")
        t = time.time()
        retrievals = []
        for i, c in enumerate(chunks):
            hits = retriever.search(c.text, top_k=max(cfg.kb_top_k, 2), vec=vectors[i], language=c.language)
            priority = max((h.get("lexical_score", 0.0) + h.get("pattern_score", 0.0) for h in hits), default=0.0)
            retrievals.append((priority, hits))
            if i % 50 == 0:
                stage("retrieval", 0.24 + 0.08 * i / len(chunks), "Matching code against the knowledge base")
        timings["retrieval_s"] = round(time.time() - t, 2)
        order = sorted(range(len(chunks)), key=lambda i: -retrievals[i][0])

        budget = cfg.max_llm_chunks if llm_ok else cfg.max_candidates_no_llm
        selected = order[:budget]
        counts["chunks_analysed"] = len(selected)
        counts["chunks_not_analysed_budget"] = max(0, len(chunks) - len(selected))

        # ---- 4b. instant triage: ranked candidates are visible immediately, before any LLM call ------
        triage_status = "pending" if llm_ok else "unverified"
        finding_ids: dict[int, int] = {}
        for i in selected:
            chunk, (priority, hits) = chunks[i], retrievals[i]
            top1, top2 = hits[0], (hits[1] if len(hits) > 1 else None)
            a0 = score_finding(top1, top2)
            tmpl0 = _template_dict(a0.cwe_id, chunk.language)
            note0 = " Waiting for the LLM to verify it." if llm_ok else ""
            finding_ids[i] = store.insert_finding(store.Finding(
                repo_url=source, chunk_id=chunk.chunk_id, file_path=chunk.repo_rel_path,
                start_line=chunk.start_line, end_line=chunk.end_line, chunk_name=chunk.name,
                chunk_kind=chunk.kind, cwe_id=a0.cwe_id, owasp_category=a0.owasp_category,
                severity_band=a0.final_band, severity_score=a0.final_score, margin=a0.margin,
                low_confidence=a0.low_confidence,
                rationale="UNVERIFIED retrieval candidate - not confirmed as a vulnerability. " + a0.rationale + note0,
                retrieved_kb_context=_kb_context(hits[:cfg.kb_top_k]), status=triage_status, scan_id=scan_id,
                code=_clip(chunk.text, MAX_CODE_STORED), retrieval_cwe=top1.get("cwe_id") or top1.get("code"),
                remediation={"template": tmpl0, "llm": None} if tmpl0 else None), db_path=db)
        counts["triage_ready_s"] = round(time.time() - t_start, 2)
        store.update_scan(scan_id, db_path=db, counts=counts)
        stage("triage", 0.34, f"{len(selected)} ranked candidates ready - verifying with the LLM" if llm_ok
              else f"{len(selected)} ranked candidates ready")

        # ---- 5-8. LLM verdict, severity, remediation, storage ---------------------------
        stats = dict(confirmed=0, needs_review=0, rejected=0, unverified=0, llm_errors=0)
        consecutive_errors = 0
        llm_disabled = None
        first_error = ""
        t = time.time()

        # Verdicts are requested by a small worker pool so that network latency overlaps (the provider's
        # RateLimiter still enforces the requests-per-minute cap). Results are consumed strictly in priority
        # order by this thread, which is the only one that touches the findings database.
        futures: dict[int, "concurrent.futures.Future"] = {}

        def _repo_context(i: int) -> list[dict]:
            ctx: list[dict] = []
            if cfg.use_rag and cfg.repo_context_k:
                for h in repo_index.search(vectors[i], top_k=cfg.repo_context_k + 1):
                    if h["chunk_id"] != chunks[i].chunk_id and len(ctx) < cfg.repo_context_k:
                        ctx.append({"path": h["repo_rel_path"], "name": h["name"],
                                    "lines": f"{h['start_line']}-{h['end_line']}", "code": h["text"]})
            return ctx

        def _judge(i: int, repo_ctx: list[dict]):
            if abort["reason"]:
                return Verdict(status="error", error=abort["reason"], use_rag=cfg.use_rag)
            c = chunks[i]
            v = analyzer.analyze(c.text, file_path=c.repo_rel_path, language=c.language,
                                 kb_hits=retrievals[i][1][:cfg.kb_top_k], repo_context=repo_ctx, use_rag=cfg.use_rag)
            if v.status == "error" and "API key" in (v.error or ""):
                abort["reason"] = v.error      # stop sending requests with a rejected key right away
            return v

        if llm_ok:
            tasks = [(i, _repo_context(i)) for i in selected]
            workers = max(1, min(int(cfg.llm_workers), 8))
            if workers > 1 and len(tasks) > 1:
                pool = DaemonPool(workers)
                futures = {i: pool.submit(_judge, i, ctx) for i, ctx in tasks}
            else:
                futures = {}
            task_ctx = dict(tasks)
        for n, i in enumerate(selected, 1):
            chunk, (priority, hits) = chunks[i], retrievals[i]
            frac = 0.34 + 0.62 * n / max(len(selected), 1)
            stage("analysis", frac, f"[{n}/{len(selected)}] {chunk.repo_rel_path} :: {chunk.name}")
            kb_hits = hits[:cfg.kb_top_k]
            top1, top2 = hits[0], (hits[1] if len(hits) > 1 else None)

            verdict = None
            verdict_error = llm_disabled or ""
            if llm_ok and not llm_disabled:
                verdict = futures[i].result() if i in futures else _judge(i, task_ctx[i])
                if verdict.status == "ok":
                    consecutive_errors = 0
                else:
                    if verdict.status == "error":
                        stats["llm_errors"] += 1
                        consecutive_errors += 1
                        first_error = first_error or verdict.error
                        if "API key" in verdict.error or consecutive_errors >= CONSECUTIVE_ERROR_LIMIT:
                            llm_disabled = verdict.error
                            abort["reason"] = verdict.error
                    elif verdict.status == "not_cached":
                        pass
                    if verdict.status != "ok":
                        verdict_error = verdict.error
                        verdict = None
                        # fall through to an unverified candidate
            if verdict is not None:
                a = score_verdict(verdict, kb_hits, kb_lookup)
                template = _template_dict(a.cwe_id, chunk.language) if a.status != "rejected" else None
                llm_fix = None
                if a.status != "rejected" and (verdict.fixed_code or verdict.fix_summary):
                    llm_fix = {"summary": verdict.fix_summary, "before": chunk.text, "after": verdict.fixed_code}
                f = store.Finding(
                    repo_url=source, chunk_id=chunk.chunk_id, file_path=chunk.repo_rel_path,
                    start_line=chunk.start_line, end_line=chunk.end_line, chunk_name=chunk.name,
                    chunk_kind=chunk.kind, cwe_id=a.cwe_id, owasp_category=a.owasp_category,
                    severity_band=a.final_band, severity_score=a.final_score, margin=round(
                        (top1["similarity"] - top2["similarity"]) if top2 else 1.0, 4),
                    low_confidence=a.low_confidence, rationale=a.rationale,
                    retrieved_kb_context=_kb_context(kb_hits), status=a.status, scan_id=scan_id,
                    code=_clip(chunk.text, MAX_CODE_STORED), retrieval_cwe=top1.get("cwe_id") or top1.get("code"),
                    retrieval_agrees=a.retrieval_agrees, llm_vulnerable=verdict.vulnerable,
                    llm_confidence=verdict.confidence,
                    llm_explanation=verdict.explanation, llm_evidence=verdict.evidence,
                    llm_model=f"{verdict.provider}/{verdict.model}" if verdict.model else verdict.provider,
                    remediation={"template": template, "llm": llm_fix} if (template or llm_fix) else None)
                stats[a.status] += 1
            else:
                a = score_finding(top1, top2)
                note = ""
                if llm_ok:
                    note = f" (LLM verdict unavailable: {verdict_error or 'unknown error'})"
                f = store.Finding(
                    repo_url=source, chunk_id=chunk.chunk_id, file_path=chunk.repo_rel_path,
                    start_line=chunk.start_line, end_line=chunk.end_line, chunk_name=chunk.name,
                    chunk_kind=chunk.kind, cwe_id=a.cwe_id, owasp_category=a.owasp_category,
                    severity_band=a.final_band, severity_score=a.final_score, margin=a.margin,
                    low_confidence=a.low_confidence,
                    rationale="UNVERIFIED retrieval candidate - not confirmed as a vulnerability. " + a.rationale + note,
                    retrieved_kb_context=_kb_context(kb_hits), status="unverified", scan_id=scan_id,
                    code=_clip(chunk.text, MAX_CODE_STORED), retrieval_cwe=top1.get("cwe_id") or top1.get("code"),
                    remediation={"template": _template_dict(a.cwe_id, chunk.language), "llm": None} if _template_dict(a.cwe_id) else None)
                stats["unverified"] += 1
            store.replace_finding(finding_ids[i], f, db_path=db)
        timings["analysis_s"] = round(time.time() - t, 2)

        counts.update(stats)
        counts["llm_calls"] = analyzer.stats["calls"]
        counts["llm_cache_hits"] = analyzer.stats["cache_hits"]
        usage = getattr(getattr(analyzer, "provider", None), "usage", None)
        if usage and (usage["prompt"] or usage["completion"]):
            counts["llm_tokens_in"], counts["llm_tokens_out"] = usage["prompt"], usage["completion"]
            counts["llm_models_used"] = {m: v["calls"] for m, v in usage["by_model"].items()}
        timings["total_s"] = round(time.time() - t_start, 2)
        warning = None
        if llm_ok and llm_disabled:
            warning = f"LLM analysis stopped early: {llm_disabled}"
        elif llm_ok and stats["llm_errors"]:
            warning = f"{stats['llm_errors']} LLM request(s) failed (first error: {first_error})"
        elif not llm_ok:
            warning = "No LLM configured: findings are unverified retrieval candidates. Set GROQ_API_KEY or GEMINI_API_KEY in .env"
        # warning is stored in the same write that marks the scan done (no window where a
        # finished scan is visible without its warning)
        store.finish_scan(scan_id, "done", warning, db_path=db, counts=counts, timings=timings)
        progress("done", 1.0, "Scan complete")
        return {"scan_id": scan_id, "mode": mode, "counts": counts, "timings": timings, "warning": warning,
                "model": f"{provider_name}/{model_name}" if model_name else provider_name}
    except ScanCancelled:
        store.finalize_pending(scan_id, "scan cancelled before the LLM judged this", db_path=db)
        store.finish_scan(scan_id, "cancelled", "cancelled by user", db_path=db, counts=counts, timings=timings)
        return {"scan_id": scan_id, "mode": mode, "counts": counts, "timings": timings, "cancelled": True}
    except Exception as e:  # noqa: BLE001 - surface any failure on the scan record
        store.finalize_pending(scan_id, "scan failed before the LLM judged this", db_path=db)
        store.finish_scan(scan_id, "failed", f"{type(e).__name__}: {e}", db_path=db, counts=counts, timings=timings)
        if os.environ.get("RAGVULN_DEBUG"):
            traceback.print_exc()
        raise
    finally:
        if pool is not None:
            abort["reason"] = "scan finished"          # queued units are skipped; requests already sent finish on their own
            pool.shutdown()
        if own_workdir:
            import shutil
            shutil.rmtree(workdir, ignore_errors=True)


def _cli() -> None:
    ap = argparse.ArgumentParser(description="Scan a repository / folder / zip for vulnerabilities (RAG + LLM).")
    ap.add_argument("source", help="local folder, .zip, or git/GitHub URL")
    ap.add_argument("--max-llm", type=int, default=40, help="max code units sent to the LLM (default 40)")
    ap.add_argument("--no-llm", action="store_true", help="skip the LLM (unverified retrieval candidates only)")
    ap.add_argument("--no-rag", action="store_true", help="LLM-only ablation: do not give the LLM retrieved context")
    ap.add_argument("--mode", default="auto", choices=["auto", "live", "replay"], help="LLM cache mode")
    ap.add_argument("--workers", type=int, default=4, help="concurrent LLM requests (default 4; rate limit still applies)")
    ap.add_argument("--include-tests", action="store_true")
    ap.add_argument("--db", default=None, help="findings database path")
    args = ap.parse_args()

    cfg = ScanConfig(max_llm_chunks=args.max_llm, use_rag=not args.no_rag, skip_tests=not args.include_tests,
                     llm_mode=args.mode, llm_workers=args.workers)
    analyzer = SecurityAnalyzer(None if args.no_llm else make_provider(), mode="live" if args.no_llm else args.mode)
    print(f"LLM: {analyzer.describe() if analyzer.available else 'none (retrieval-only, findings are UNVERIFIED)'}")

    def show(stage_name, frac, msg):
        print(f"  [{frac*100:5.1f}%] {stage_name:<10} {msg}")

    res = run_scan(args.source, cfg, analyzer=analyzer, db_path=args.db, progress=show)
    print(f"\nScan #{res['scan_id']} finished in {res['timings']['total_s']}s  mode={res['mode']}")
    c = res["counts"]
    print(f"  files analysed: {c['files_analysable']}   code units: {c['chunks_total']}   sent to analysis: {c['chunks_analysed']}")
    print(f"  confirmed: {c['confirmed']}   needs review: {c['needs_review']}   rejected by LLM: {c['rejected']}   unverified: {c['unverified']}")
    print(f"  LLM calls: {c['llm_calls']}   cache hits: {c['llm_cache_hits']}   errors: {c['llm_errors']}")
    if res.get("warning"):
        print(f"  WARNING: {res['warning']}")
    for f in store.query_findings(scan_id=res["scan_id"], status=("confirmed", "needs_review", "unverified"),
                                  order="severity", db_path=args.db or store._DEFAULT_DB_PATH):
        print(f"  {f.severity_band:<8} {f.cwe_id or f.owasp_category or '?':<8} {f.status:<12} {f.file_path}:{f.start_line}  {f.chunk_name}")


if __name__ == "__main__":
    _cli()
