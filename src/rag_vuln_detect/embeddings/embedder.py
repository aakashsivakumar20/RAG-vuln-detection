"""
Embedding Service.

Responsibility (per docs/chapter3_methodology.md): convert code chunks and
knowledge-base text into vector embeddings for the vector store.

--------------------------------------------------------------------------
IMPLEMENTATION NOTE (read this before assuming a mismatch with Chapter 3):
--------------------------------------------------------------------------
Chapter 3 named a "code-specialised embedding model" (e.g. a transformer such
as CodeBERT/UniXcoder, or an API-based embedding model) as the target for
this module. Building this prototype, the build environment's network policy
blocks Hugging Face Hub (huggingface.co) and Stanford NLP's direct file host,
which is where such pretrained transformer weights are normally fetched from
-- confirmed via direct connection tests, not assumed. GitHub-hosted model
distribution (github.com / raw.githubusercontent.com / objects.githubusercontent.com)
IS reachable, so this module uses averaged GloVe word embeddings
(`glove-wiki-gigaword-100`, via gensim, distributed through the gensim-data
GitHub releases) as the Review 3 embedding backbone: a genuine, pretrained,
dense semantic embedding -- not a hand-rolled placeholder -- just not a
code-specific transformer.

Two refinements are applied on top of plain averaging, since a first sanity
check (see knowledge_base/build_kb.py) showed plain averaging mis-ranking a
classic SQL-injection snippet below Path Traversal:
  1. Identifiers are split on camelCase/snake_case boundaries before lookup
     (`fooBar` / `foo_bar` -> "foo", "bar") since GloVe was trained on
     natural-language tokens, not raw source identifiers.
  2. Tokens are weighted by IDF computed over the knowledge-base corpus
     (embeddings/idf.py) before averaging, so generic shared tokens (e.g.
     "user", "select") don't drown out the tokens that actually distinguish
     one weakness from another.

This is an explicit, documented scope substitution for Review 3, not a
silent shortcut: the module's public function signature (`embed_texts`)
is deliberately identical to what a transformer-backed implementation would
expose, so swapping in a code-specialised transformer later (once API/model
access is available) requires no change to any calling code -- only to this
file. See docs/chapter4_implementation.md Sec 4.2 for the full discussion,
including the measured before/after retrieval-accuracy numbers.
"""

from __future__ import annotations

import re
import time
from functools import lru_cache

import numpy as np

from rag_vuln_detect.embeddings.idf import weight_for

MODEL_NAME = "glove-wiki-gigaword-100 (gensim-data)"
EMBEDDING_DIM = 100

_IDENTIFIER_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")
_CAMEL_SPLIT_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


@lru_cache(maxsize=1)
def _get_model():
    import gensim.downloader as api
    return api.load("glove-wiki-gigaword-100")


def tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    for raw in _IDENTIFIER_SPLIT_RE.split(text):
        if not raw:
            continue
        for piece in _CAMEL_SPLIT_RE.split(raw):
            if piece:
                tokens.append(piece.lower())
    return tokens


def embed_texts(
    texts: list[str],
    idf: dict[str, float] | None = None,
    batch_size: int = 32,
) -> tuple[np.ndarray, float]:
    """Returns (embeddings [n, EMBEDDING_DIM] float32 L2-normalised, elapsed_seconds).

    If `idf` is given (see embeddings/idf.py), tokens are weighted by IDF
    before averaging; otherwise every known token is weighted equally.
    """
    model = _get_model()
    start = time.time()
    vectors = np.zeros((len(texts), EMBEDDING_DIM), dtype="float32")
    for i, text in enumerate(texts):
        tokens = tokenize(text)
        weighted_sum = np.zeros(EMBEDDING_DIM, dtype="float32")
        weight_total = 0.0
        for t in tokens:
            if t in model:
                w = weight_for(t, idf)
                weighted_sum += model[t] * w
                weight_total += w
        v = weighted_sum / weight_total if weight_total > 1e-8 else weighted_sum
        norm = np.linalg.norm(v)
        vectors[i] = v / norm if norm > 1e-8 else v
    elapsed = time.time() - start
    return vectors.astype("float32"), elapsed


if __name__ == "__main__":
    sample = [
        "def add(a, b):\n    return a + b",
        "query = \"SELECT * FROM users WHERE id = '\" + user_input + \"'\"",
    ]
    vecs, secs = embed_texts(sample)
    print(f"Embedded {len(sample)} texts in {secs:.3f}s -> shape {vecs.shape}")
    print("Cosine sim between the two samples:", float(vecs[0] @ vecs[1]))
