"""
Vector Store module (FAISS).

Responsibility (per docs/chapter3_methodology.md): store embeddings for
similarity search. Two separate FAISS indices are used, matching Chapter 3's
architecture diagram:
  - a per-scan "repository code index" (rebuilt per repository, in-memory)
  - a persistent "security knowledge base index" (built once from OWASP/CWE
    content, saved to disk, and reused across scans)

Chapter 3 lists FAISS / ChromaDB / Pinecone as candidates and defers the
final choice to implementation. FAISS is used here for Review 3: it is
local (no network dependency or API key, which matters given this build
environment's network policy — see embeddings/embedder.py), and is well
suited to prototype-scale evaluation per Chapter 3 Sec 3.4/3.5.
"""

from __future__ import annotations

import json
import os

import faiss
import numpy as np


class VectorIndex:
    """A thin, typed wrapper around a flat FAISS index (cosine similarity via
    inner product on L2-normalised vectors) plus the metadata for each entry."""

    def __init__(self, dim: int):
        self.dim = dim
        self.index = faiss.IndexFlatIP(dim)
        self.metadata: list[dict] = []

    def add(self, vectors: np.ndarray, metadata: list[dict]) -> None:
        assert vectors.shape[0] == len(metadata), "vectors/metadata length mismatch"
        assert vectors.shape[1] == self.dim, f"expected dim {self.dim}, got {vectors.shape[1]}"
        self.index.add(vectors)
        self.metadata.extend(metadata)

    def search(self, query_vector: np.ndarray, top_k: int = 5) -> list[dict]:
        if self.index.ntotal == 0:
            return []
        query_vector = query_vector.reshape(1, -1).astype("float32")
        scores, indices = self.index.search(query_vector, min(top_k, self.index.ntotal))
        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx == -1:
                continue
            entry = dict(self.metadata[idx])
            entry["similarity"] = float(score)
            results.append(entry)
        return results

    def save(self, path_prefix: str) -> None:
        os.makedirs(os.path.dirname(path_prefix) or ".", exist_ok=True)
        faiss.write_index(self.index, f"{path_prefix}.faiss")
        with open(f"{path_prefix}.meta.json", "w") as f:
            json.dump({"dim": self.dim, "metadata": self.metadata}, f)

    @classmethod
    def load(cls, path_prefix: str) -> "VectorIndex":
        with open(f"{path_prefix}.meta.json") as f:
            data = json.load(f)
        obj = cls(dim=data["dim"])
        obj.index = faiss.read_index(f"{path_prefix}.faiss")
        obj.metadata = data["metadata"]
        return obj

    def __len__(self) -> int:
        return self.index.ntotal


if __name__ == "__main__":
    from rag_vuln_detect.embeddings.embedder import embed_texts, EMBEDDING_DIM

    idx = VectorIndex(dim=EMBEDDING_DIM)
    texts = ["def login(user, password): ...", "def render_page(html): ..."]
    vecs, _ = embed_texts(texts)
    idx.add(vecs, [{"text": t} for t in texts])

    query_vecs, _ = embed_texts(["authenticate a user with a password"])
    print(idx.search(query_vecs[0], top_k=2))
