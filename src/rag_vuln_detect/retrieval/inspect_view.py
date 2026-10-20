"""
Retrieval "x-ray" for the dashboard Inspector page.

Re-runs the SAME code path the scanner uses (HybridRetriever.components) on one code chunk and returns every
intermediate number, so a person can see why a given CWE came out on top:

  * tokens           how the GloVe embedder sees the text: which words exist in the vocabulary, their IDF weight and
                     their share of the averaged vector
  * lexical_tokens   the identifier tokens BM25 searches with, their BM25 IDF and which KB entries contain them
  * candidates       per KB entry: dense cosine (FAISS), BM25, both min-max normalised, static-rule score, prior and
                     the fused score. The UI recomputes the fused score from these when the sliders move.
  * rule_hits        static sink rules that fired (rule id, CWE, weight, line, matched text, regex)
  * prompt           the exact system + user prompt the LLM would receive for the top-k entries
"""
from __future__ import annotations

import threading

import numpy as np

from rag_vuln_detect.embeddings.embedder import embed_texts, tokenize
from rag_vuln_detect.embeddings.idf import weight_for
from rag_vuln_detect.llm import analyzer
from rag_vuln_detect.retrieval import patterns
from rag_vuln_detect.retrieval.hybrid import (HybridRetriever, lexical_tokens, record_id, DEFAULT_ALPHA,
                                              DEFAULT_BETA, DEFAULT_PRIOR)

_lock = threading.Lock()
_cache: dict = {}
MAX_CODE = 20000


def get_retriever() -> HybridRetriever:
    with _lock:
        if "r" not in _cache:
            from rag_vuln_detect.knowledge_base.build_kb import load_knowledge_base
            kb_index, idf = load_knowledge_base()
            _cache["r"] = HybridRetriever(kb_index, idf)
        return _cache["r"]


def _glove_vocab():
    from rag_vuln_detect.embeddings.embedder import _get_model
    return _get_model()


def embedder_tokens(code: str, idf: dict) -> list[dict]:
    model = _glove_vocab()
    rows, total = [], 0.0
    for t in tokenize(code):
        known = t in model
        w = weight_for(t, idf) if known else 0.0
        total += w
        rows.append({"token": t, "in_vocab": known, "idf": round(float(weight_for(t, idf)), 3), "weight": w})
    # merge repeated tokens (count them), keep first-seen order
    merged: dict[str, dict] = {}
    for r in rows:
        m = merged.setdefault(r["token"], {"token": r["token"], "in_vocab": r["in_vocab"], "idf": r["idf"],
                                           "count": 0, "weight": 0.0})
        m["count"] += 1
        m["weight"] += r["weight"]
    out = []
    for m in merged.values():
        m["share"] = round(m["weight"] / total, 4) if total > 0 else 0.0
        m["in_idf_table"] = m["token"] in idf
        del m["weight"]
        out.append(m)
    out.sort(key=lambda x: -x["share"])
    return out


def inspect_code(code: str, language: str | None = None, *, alpha: float | None = None, beta: float | None = None,
                 top_k: int = 6, file_path: str = "snippet", kb_hits_override: list | None = None) -> dict:
    code = (code or "")[:MAX_CODE]
    r = get_retriever()
    vec = embed_texts([code], idf=r.idf)[0][0]
    c = r.components(code, language, vec, alpha, beta)
    recs = r.records
    n = len(recs)

    # BM25 query tokens, their IDF and document frequency
    qtok = sorted(set(lexical_tokens(code)))
    lex_rows = []
    for t in qtok:
        docs = [i for i in range(n) if t in r._tf[i]]
        lex_rows.append({"token": t, "idf": round(float(r._idf[t]), 3) if t in r._idf else 0.0,
                         "kb_docs": len(docs), "matches": [record_id(recs[i]) for i in docs[:8]]})
    lex_rows.sort(key=lambda x: (-x["idf"] if x["kb_docs"] else 1, x["token"]))

    prior = r._prior_vector()
    fused = c["fused"]
    pool: set[int] = set()
    for arr in (fused, c["dense"], c["lexical"], c["pattern"]):
        pool.update(int(i) for i in np.argsort(-arr)[:15])
    rank_default = {int(i): k + 1 for k, i in enumerate(np.argsort(-fused))}
    rank_dense = {int(i): k + 1 for k, i in enumerate(np.argsort(-c["dense"]))}
    rank_bm25 = {int(i): k + 1 for k, i in enumerate(np.argsort(-c["lexical"]))}
    qset = set(qtok)
    cands = []
    for i in sorted(pool, key=lambda j: rank_default[j]):
        rec = recs[i]
        matched = sorted(((t, round(float(r._idf[t]), 2)) for t in qset if t in r._tf[i]), key=lambda x: -x[1])
        cands.append({
            "id": record_id(rec), "name": rec.get("name", ""), "tier": rec.get("tier") or rec.get("standard"),
            "dense": round(float(c["dense"][i]), 4), "dense_norm": round(float(c["dense_norm"][i]), 4),
            "bm25": round(float(c["lexical"][i]), 3), "bm25_norm": round(float(c["lexical_norm"][i]), 4),
            "pattern": round(float(c["pattern"][i]), 4), "prior": round(float(prior[i]), 4),
            "fused": round(float(fused[i]), 4),
            "rank": rank_default[i], "rank_dense": rank_dense[i], "rank_bm25": rank_bm25[i],
            "matched_tokens": [{"token": t, "idf": w} for t, w in matched[:12]],
            "rule_ids": sorted({h.rule.id for h in c["hits"] if h.rule.cwe == rec.get("cwe_id")}),
        })

    hits = [{"rule": h.rule.id, "cwe": h.rule.cwe, "weight": h.rule.weight, "line": h.line, "text": h.text,
             "note": h.rule.note, "regex": h.rule.source} for h in c["hits"]]

    order = np.argsort(-fused)[:max(top_k, 2)]
    top_hits = kb_hits_override
    if top_hits is None:
        top_hits = []
        for i in order:
            d = dict(recs[i]); d["similarity"] = round(float(fused[i]), 4)
            top_hits.append(d)
    system, user = analyzer.build_prompt(code, file_path=file_path, language=language or "unknown",
                                         kb_hits=top_hits[:top_k], repo_context=None)
    return {
        "code": code, "language": language, "alpha": c["alpha"], "beta": c["beta"], "prior_bonus": r.prior,
        "defaults": {"alpha": DEFAULT_ALPHA, "beta": DEFAULT_BETA, "prior": DEFAULT_PRIOR},
        "kb_size": n, "chars": len(code), "tokens": embedder_tokens(code, r.idf), "lexical_tokens": lex_rows,
        "candidates": cands, "rule_hits": hits, "rules_loaded": len(r.rules),
        "prompt": {"system": system, "user": user, "kb_top_k": top_k},
    }
