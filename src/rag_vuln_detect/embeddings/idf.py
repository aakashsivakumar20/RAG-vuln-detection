"""
IDF weighting for the GloVe-averaging embedder.

Plain mean-of-word-vectors treats every token equally, so generic tokens
shared across many KB entries (e.g. "select", "user", "function") can
dominate the average and drown out the few tokens that actually distinguish
one weakness from another. This module computes IDF (inverse document
frequency) over the knowledge-base corpus and lets embed_texts() use it as a
per-token weight — the standard, well-known fix for this failure mode
(a simplified version of SIF / TF-IDF weighted word-vector averaging).

This was added after an initial sanity check (see build_kb.py) showed a
classic SQL-injection snippet retrieving CWE-22 (Path Traversal) above
CWE-89 (SQL Injection) with unweighted averaging — see
docs/chapter4_implementation.md Sec 4.2 for the before/after numbers.
"""

from __future__ import annotations

import json
import math
import os

_DEFAULT_IDF = 1.0  # weight for tokens never seen in the reference corpus


def compute_idf(corpus_texts: list[str], tokenize_fn) -> dict[str, float]:
    n_docs = len(corpus_texts)
    doc_freq: dict[str, int] = {}
    for text in corpus_texts:
        seen = set(tokenize_fn(text))
        for tok in seen:
            doc_freq[tok] = doc_freq.get(tok, 0) + 1
    return {tok: math.log((n_docs + 1) / (df + 1)) + 1.0 for tok, df in doc_freq.items()}


def save_idf(idf: dict[str, float], path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(idf, f)


def load_idf(path: str) -> dict[str, float]:
    with open(path) as f:
        return json.load(f)


def weight_for(token: str, idf: dict[str, float] | None) -> float:
    if idf is None:
        return 1.0
    return idf.get(token, _DEFAULT_IDF)
