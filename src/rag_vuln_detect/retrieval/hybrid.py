"""
Hybrid retrieval over the Security Knowledge Base.

Dense signal  : cosine similarity between the IDF-weighted GloVe embedding of a
                code chunk and each KB entry (embeddings/embedder.py).
Lexical signal: BM25 between the chunk's identifier tokens and each KB entry's
                text plus its project-authored `kb_signals.json` indicators
                (API names / idioms such as `innerHTML`, `shell=True`, `pickle.loads`).

Why hybrid: averaged word vectors compress most source code into a narrow cone
(raw cosine scores cluster in ~0.85-0.95 regardless of correctness) and cannot
tell a missing authorization check from a present one. Exact API tokens are far
more discriminative, which is also why Vul-RAG (L1) retrieves with BM25. The two
scores live on different scales, so each is min-max normalised across the KB
for the query before fusion:

    score = alpha * dense_norm + (1 - alpha) * bm25_norm

`alpha` is fitted on the DEV benchmark only (evaluation/benchmark_snippets.json);
the untouched held-out set (evaluation/heldout_snippets.json) measures how well
the fit generalises.
"""

from __future__ import annotations

import json
import math
import os
import re

import numpy as np

from rag_vuln_detect.embeddings.embedder import embed_texts
from rag_vuln_detect.retrieval import patterns

_HERE = os.path.dirname(os.path.abspath(__file__))
_SIGNALS_PATH = os.path.join(_HERE, "..", "knowledge_base", "kb_signals.json")

DEFAULT_BETA = 1.0   # weight of the static-rule evidence (retrieval/patterns.py) added to the fused score
DEFAULT_PRIOR = 0.05  # small bonus for the OWASP/CWE-Top-25 entries (base-rate prior); 0 = off
DEFAULT_ALPHA = 0.5  # overwritten by the value fitted on the dev set (see evaluation/tune_retrieval.py)
BM25_K1 = 1.5
BM25_B = 0.75

_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_STOP = {
    "the", "a", "an", "of", "to", "in", "and", "or", "is", "are", "be", "by", "for", "as", "on",
    "with", "that", "this", "it", "from", "at", "which", "can", "may", "not", "no", "but", "if",
    # Syntax keywords and ubiquitous builtins of Python/JS/TS. They occur in nearly every code chunk but in only a
    # few knowledge-base entries, so KB-level IDF wrongly rated them as highly discriminative; found by counting
    # which KB entries attract the most unrelated chunks (hubness) when the retriever is run over unlabelled code.
    "def", "class", "return", "else", "elif", "for", "while", "elseif", "do", "break", "continue", "pass", "try",
    "except", "finally", "raise", "throw", "catch", "import", "export", "default", "self", "cls", "none", "null",
    "undefined", "true", "false", "const", "let", "var", "function", "new", "async", "await", "yield", "lambda",
    "typeof", "instanceof", "del", "global", "nonlocal", "assert", "print", "len", "str", "int", "args", "kwargs",
    "param", "params", "arg", "obj", "tmp", "foo", "bar", "res", "ret", "val", "num",
}


def lexical_tokens(text: str) -> list[str]:
    """Identifier-aware tokens: each identifier contributes its camel/snake
    pieces and (if it was split) the whole lower-cased identifier too, so exact
    API names such as `innerHTML` match even when pieces are common words."""
    out: list[str] = []
    for raw in _SPLIT_RE.split(text):
        if not raw:
            continue
        pieces = [p.lower() for p in _CAMEL_RE.split(raw) if p]
        # single characters (f-string prefix, loop variables) and bare numbers (status codes, versions) never name an API
        out.extend(p for p in pieces if p not in _STOP and len(p) > 1 and not p.isdigit())
        if len(pieces) > 1:
            out.append(raw.lower())
    return out


def load_signals(path: str = _SIGNALS_PATH) -> dict[str, str]:
    try:
        with open(path) as f:
            return {k: v for k, v in json.load(f).items() if not k.startswith("_")}
    except FileNotFoundError:
        return {}


def record_id(rec: dict) -> str:
    return rec.get("cwe_id") or rec.get("code") or rec.get("id")


def record_text(rec: dict) -> str:
    if rec.get("standard") == "CWE":
        return f"{rec['cwe_id']} {rec['name']}. {rec['description']} {rec.get('example_pattern', '')}"
    return f"{rec.get('code', '')} {rec['name']}. {rec['description']}"


def _minmax(x: np.ndarray) -> np.ndarray:
    lo, hi = float(x.min()), float(x.max())
    if hi - lo < 1e-9:
        return np.zeros_like(x)
    return (x - lo) / (hi - lo)


class HybridRetriever:
    def __init__(self, kb_index, idf: dict[str, float], alpha: float | None = None,
                 use_signals: bool = True, use_rules: bool = True, beta: float | None = None,
                 prior: float | None = None):
        self.kb_index = kb_index
        self.idf = idf
        self.alpha = DEFAULT_ALPHA if alpha is None else alpha
        self.beta = DEFAULT_BETA if beta is None else beta
        self.prior = DEFAULT_PRIOR if prior is None else prior
        self.rules = patterns.load_rules() if use_rules else []
        self.records = kb_index.metadata
        signals = load_signals() if use_signals else {}
        self._docs = [lexical_tokens(record_text(r) + " " + signals.get(record_id(r), ""))
                      for r in self.records]
        n = len(self._docs)
        self._avgdl = sum(len(d) for d in self._docs) / max(n, 1)
        df: dict[str, int] = {}
        for d in self._docs:
            for t in set(d):
                df[t] = df.get(t, 0) + 1
        self._idf = {t: math.log(1 + (n - c + 0.5) / (c + 0.5)) for t, c in df.items()}
        self._tf = [self._count(d) for d in self._docs]

    @staticmethod
    def _count(tokens: list[str]) -> dict[str, int]:
        c: dict[str, int] = {}
        for t in tokens:
            c[t] = c.get(t, 0) + 1
        return c

    def bm25_scores(self, code: str) -> np.ndarray:
        q = set(lexical_tokens(code))
        scores = np.zeros(len(self._docs), dtype="float64")
        for i, tf in enumerate(self._tf):
            dl = len(self._docs[i])
            s = 0.0
            for t in q:
                f = tf.get(t)
                if not f:
                    continue
                s += self._idf[t] * f * (BM25_K1 + 1) / (f + BM25_K1 * (1 - BM25_B + BM25_B * dl / self._avgdl))
            scores[i] = s
        return scores

    def dense_scores(self, code: str, vec: np.ndarray | None = None) -> np.ndarray:
        """Cosine similarity to every KB entry. Pass a precomputed chunk embedding as `vec`
        to avoid embedding the same text twice (the scan pipeline embeds all chunks once)."""
        if vec is None:
            vecs, _ = embed_texts([code], idf=self.idf)
            vec = vecs[0]
        hits = self.kb_index.search(vec, top_k=len(self.records))
        by_id = {record_id(h): h["similarity"] for h in hits}
        return np.asarray([by_id[record_id(r)] for r in self.records], dtype="float64")

    def rule_hits(self, code: str, language: str | None = None):
        return patterns.scan(code, language, self.rules) if self.rules else []

    def _pattern_vector(self, hits) -> np.ndarray:
        scores = patterns.cwe_scores(hits)
        return np.asarray([scores.get(r.get("cwe_id"), 0.0) for r in self.records], dtype="float64")

    def _prior_vector(self) -> np.ndarray:
        if not self.prior:
            return np.zeros(len(self.records))
        return np.asarray([self.prior if (r.get("standard") == "OWASP" or r.get("tier") != "extended") else 0.0
                           for r in self.records], dtype="float64")

    def components(self, code: str, language: str | None = None, vec: np.ndarray | None = None,
                   alpha: float | None = None, beta: float | None = None) -> dict:
        """Every intermediate score the ranking is built from (used by search() and the dashboard Inspector)."""
        a = self.alpha if alpha is None else alpha
        b = self.beta if beta is None else beta
        dense = self.dense_scores(code, vec)
        lex = self.bm25_scores(code)
        hits = self.rule_hits(code, language)
        pat = self._pattern_vector(hits)
        dn, ln = _minmax(dense), _minmax(lex)
        fused = a * dn + (1 - a) * ln + b * pat + self._prior_vector()
        return {"dense": dense, "lexical": lex, "dense_norm": dn, "lexical_norm": ln, "pattern": pat,
                "fused": fused, "hits": hits, "alpha": a, "beta": b}

    def search(self, code: str, top_k: int = 5, alpha: float | None = None,
               vec: np.ndarray | None = None, language: str | None = None,
               beta: float | None = None) -> list[dict]:
        c = self.components(code, language, vec, alpha, beta)
        fused = c["fused"]
        order = np.argsort(-fused)[:top_k]
        results = []
        for i in order:
            r = dict(self.records[i])
            r["similarity"] = round(float(fused[i]), 4)
            r["dense_similarity"] = round(float(c["dense"][i]), 4)
            r["lexical_score"] = round(float(c["lexical"][i]), 4)
            r["pattern_score"] = round(float(c["pattern"][i]), 4)
            results.append(r)
        return results
