"""Shared helpers for retrieval evaluation (dev tuning + held-out reporting)."""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from rag_vuln_detect.knowledge_base.build_kb import load_knowledge_base
from rag_vuln_detect.retrieval.hybrid import HybridRetriever, record_id
from rag_vuln_detect.embeddings.embedder import embed_texts

_HERE = os.path.dirname(os.path.abspath(__file__))


def load_set(name: str) -> list[dict]:
    path = {"dev": "benchmark_snippets.json", "heldout": "heldout_snippets.json",
            "extended": "extended_snippets.json", "heldout2": "heldout2_snippets.json",
            "langs": "langs_snippets.json"}[name]
    with open(os.path.join(_HERE, path)) as f:
        return json.load(f)["snippets"]


def ranks_for(snippets, rank_fn, k=10):
    rows = []
    for s in snippets:
        labels = rank_fn(s["code"], k, s.get("language"))
        gold = s["expected_cwe"]
        rank = labels.index(gold) + 1 if gold in labels else None
        rows.append({"id": s["id"], "expected": gold, "pred": labels, "rank": rank})
    return rows


def metrics(rows) -> dict:
    n = len(rows)
    def rec(k): return sum(1 for r in rows if r["rank"] and r["rank"] <= k) / n
    mrr = sum(1 / r["rank"] for r in rows if r["rank"]) / n
    # top6 = how many entries the LLM verdict step is shown in the scan pipeline (kb_top_k=6)
    return {"n": n, "top1": rec(1), "top3": rec(3), "top5": rec(5), "top6": rec(6), "top10": rec(10), "mrr": mrr}


def dense_rank_fn(kb_index, idf, use_idf=True):
    def fn(code, k, language=None):
        vec, _ = embed_texts([code], idf=idf if use_idf else None)
        return [record_id(h) for h in kb_index.search(vec[0], top_k=k)]
    return fn


def hybrid_rank_fn(retriever, alpha=None, beta=None):
    def fn(code, k, language=None):
        return [record_id(h) for h in retriever.search(code, top_k=k, alpha=alpha, language=language, beta=beta)]
    return fn


def fmt(m):
    return (f"top1={m['top1']:.1%} top3={m['top3']:.1%} top5={m['top5']:.1%} top6={m['top6']:.1%} "
            f"top10={m['top10']:.1%} MRR={m['mrr']:.3f}")


# Secondary, project-defined "families" of closely related weaknesses (siblings / parent-child in the CWE catalogue,
# assigned by this project). The extended knowledge base contains fine-grained children such as CWE-80 or CWE-23, so a
# retriever that returns CWE-80 for a CWE-79 snippet is a near miss, not an unrelated hit. Reported next to, never
# instead of, the strict exact-match numbers.
FAMILIES = [
    {"CWE-79", "CWE-80", "CWE-81", "CWE-82", "CWE-83", "CWE-84", "CWE-85", "CWE-86", "CWE-87"},
    {"CWE-89", "CWE-564"},
    {"CWE-77", "CWE-78", "CWE-88"},
    {"CWE-22", "CWE-23", "CWE-36", "CWE-73"},
    {"CWE-94", "CWE-95", "CWE-96", "CWE-917", "CWE-1336"},
    {"CWE-284", "CWE-285", "CWE-862", "CWE-863", "CWE-639", "CWE-566"},
    {"CWE-306", "CWE-287", "CWE-288", "CWE-290"},
    {"CWE-20", "CWE-129", "CWE-606"},
    {"CWE-200", "CWE-209", "CWE-201", "CWE-497", "CWE-359", "CWE-532", "CWE-213"},
    {"CWE-770", "CWE-400", "CWE-789", "CWE-774", "CWE-409", "CWE-405"},
    # added in v2 for the memory-safety and cryptography entries that the C / Rust / Java snippets exercise
    {"CWE-120", "CWE-121", "CWE-122", "CWE-787", "CWE-125", "CWE-131", "CWE-788"},
    {"CWE-327", "CWE-328", "CWE-916", "CWE-759", "CWE-326"},
    {"CWE-330", "CWE-338", "CWE-335", "CWE-331"},
]


def same_family(a: str, b: str) -> bool:
    return a == b or any(a in f and b in f for f in FAMILIES)


def family_metrics(rows) -> dict:
    """top-1/top-3 where a hit from the same family as the gold CWE also counts."""
    n = len(rows)
    def hit(r, k):
        return any(same_family(p, r["expected"]) for p in r["pred"][:k])
    return {"family_top1": sum(hit(r, 1) for r in rows) / n, "family_top3": sum(hit(r, 3) for r in rows) / n}
