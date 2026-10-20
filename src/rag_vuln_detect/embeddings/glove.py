"""
Pure-numpy GloVe word-vector loader (replaces the former gensim dependency).

Why this exists
---------------
The embedding backbone is the pretrained `glove-wiki-gigaword-100` vectors
(Pennington et al., Stanford; distributed through the gensim-data GitHub
releases). Loading them previously needed the `gensim` package, which has no
prebuilt wheel for Python 3.14 and therefore could not be installed on a
standard Windows machine without a C compiler. The vectors themselves are just
a text table ("word v1 ... v100" per line), so this module reads them directly
with numpy -- no extra dependency, identical vectors, identical retrieval
results (verified by evaluation/run_benchmark.py).

Resolution order for the vector table (first hit wins):
  1. data/glove100_top<N>.npz   -- bundled, trimmed to the N most frequent
                                   words, stored as float16 (shipped with the
                                   repository so no download is needed).
  2. $GLOVE_PATH                -- a full glove-wiki-gigaword-100(.gz|.txt) file.
  3. ~/gensim-data/glove-wiki-gigaword-100/ (if gensim-data cached it earlier).
  4. Download of the original release file into data/cache/ (needs internet).

GloVe files are sorted by corpus frequency, so trimming to the top N words
keeps the vocabulary that matters for identifiers and English security
vocabulary while shrinking the table from ~134 MB to a few MB.
"""

from __future__ import annotations

import glob
import gzip
import io
import os
import urllib.request
from functools import lru_cache

import numpy as np

EMBEDDING_DIM = 100
RELEASE_URL = (
    "https://github.com/RaRe-Technologies/gensim-data/releases/download/"
    "glove-wiki-gigaword-100/glove-wiki-gigaword-100.gz"
)

_HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.abspath(os.path.join(_HERE, "..", "..", "..", "data"))


class GloveVectors:
    """Minimal read-only word -> vector table (supports `in` and `[]`)."""

    def __init__(self, words: list[str], matrix: np.ndarray):
        self.words = words
        self.matrix = matrix.astype("float32", copy=False)
        self._index = {w: i for i, w in enumerate(words)}

    def __contains__(self, word: str) -> bool:
        return word in self._index

    def __getitem__(self, word: str) -> np.ndarray:
        return self.matrix[self._index[word]]

    def __len__(self) -> int:
        return len(self.words)


def _bundled_npz() -> str | None:
    def size(path: str) -> int:
        digits = "".join(c for c in os.path.basename(path) if c.isdigit())
        return int(digits) if digits else 0

    candidates = glob.glob(os.path.join(DATA_DIR, "glove100_top*.npz"))
    return max(candidates, key=size) if candidates else None


def _read_text_table(path: str, max_words: int | None = None) -> GloveVectors:
    opener = gzip.open if path.endswith(".gz") else open
    words: list[str] = []
    rows: list[np.ndarray] = []
    with opener(path, "rt", encoding="utf-8", errors="replace") as f:
        first = f.readline()
        parts = first.rstrip().split(" ")
        # word2vec text format has a "<count> <dim>" header; raw GloVe does not.
        if not (len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit()):
            f = io.StringIO(first + f.read())
        for line in f:
            if max_words is not None and len(words) >= max_words:
                break
            parts = line.rstrip().split(" ")
            if len(parts) != EMBEDDING_DIM + 1:
                continue
            words.append(parts[0])
            rows.append(np.asarray(parts[1:], dtype="float32"))
    return GloveVectors(words, np.vstack(rows))


def _find_full_file() -> str | None:
    env = os.environ.get("GLOVE_PATH")
    if env and os.path.exists(env):
        return env
    for p in (
        os.path.expanduser("~/gensim-data/glove-wiki-gigaword-100/glove-wiki-gigaword-100.gz"),
        os.path.join(DATA_DIR, "cache", "glove-wiki-gigaword-100.gz"),
    ):
        if os.path.exists(p):
            return p
    return None


def download_full(dest_dir: str | None = None) -> str:
    dest_dir = dest_dir or os.path.join(DATA_DIR, "cache")
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, "glove-wiki-gigaword-100.gz")
    tmp = dest + ".part"
    print(f"Downloading GloVe vectors (~134 MB) to {dest} ...")
    urllib.request.urlretrieve(RELEASE_URL, tmp)
    os.replace(tmp, dest)
    return dest


@lru_cache(maxsize=1)
def load_glove() -> GloveVectors:
    npz = _bundled_npz()
    if npz:
        z = np.load(npz, allow_pickle=False)
        return GloveVectors(z["words"].tolist(), z["vectors"])
    full = _find_full_file() or download_full()
    return _read_text_table(full)


def build_subset(top_n: int, out_path: str | None = None, source: str | None = None) -> str:
    """Create the bundled trimmed table from a full GloVe file."""
    source = source or _find_full_file() or download_full()
    gv = _read_text_table(source, max_words=top_n)
    out_path = out_path or os.path.join(DATA_DIR, f"glove100_top{top_n // 1000}k.npz")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    np.savez_compressed(
        out_path,
        words=np.asarray(gv.words, dtype=str),
        vectors=gv.matrix.astype("float16"),
    )
    return out_path


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Build the bundled trimmed GloVe table.")
    ap.add_argument("--top", type=int, default=100000)
    ap.add_argument("--source", default=None)
    args = ap.parse_args()
    p = build_subset(args.top, source=args.source)
    print(f"Wrote {p} ({os.path.getsize(p) / 1e6:.1f} MB)")
