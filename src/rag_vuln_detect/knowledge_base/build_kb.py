"""
Security Knowledge Base construction.

Responsibility (per docs/chapter3_methodology.md): chunk OWASP Top 10 and
CWE documentation by weakness/category and embed into a persistent vector
collection, built once and reused across scans (not rebuilt per repository).

Run directly to (re)build the persistent index under
rag-vuln-detect-project/data/kb_index.* (and the IDF weights the embedder
uses, under data/kb_idf.json — see embeddings/idf.py).
"""

from __future__ import annotations

import json
import os

from rag_vuln_detect.embeddings.embedder import embed_texts, tokenize, EMBEDDING_DIM
from rag_vuln_detect.embeddings.idf import compute_idf, save_idf, load_idf
from rag_vuln_detect.vectorstore.faiss_store import VectorIndex

_HERE = os.path.dirname(os.path.abspath(__file__))
_ENTRIES_PATH = os.path.join(_HERE, "kb_entries.json")
_DATA_DIR = os.path.join(_HERE, "..", "..", "..", "data")
_DEFAULT_INDEX_PATH = os.path.join(_DATA_DIR, "kb_index")
_DEFAULT_IDF_PATH = os.path.join(_DATA_DIR, "kb_idf.json")


def _entry_to_text(entry: dict, standard: str) -> str:
    """The text that actually gets embedded for one KB entry — combines the
    fields most likely to lexically/semantically overlap with real code."""
    if standard == "CWE":
        return (
            f"{entry['cwe_id']} {entry['name']}. {entry['description']} "
            f"Typical pattern: {entry.get('example_pattern', '')}"
        )
    return f"{entry['code']} {entry['name']}. {entry['description']}"


def load_kb_records() -> list[dict]:
    with open(_ENTRIES_PATH) as f:
        data = json.load(f)
    records = []
    for e in data["owasp_top10_2025"]:
        records.append({"standard": "OWASP", **e})
    for e in data["cwe_top25_2025"]:
        records.append({"standard": "CWE", **e})
    return records


def build_knowledge_base(
    index_path: str = _DEFAULT_INDEX_PATH, idf_path: str = _DEFAULT_IDF_PATH
) -> tuple[VectorIndex, dict]:
    records = load_kb_records()
    texts = [_entry_to_text(r, r["standard"]) for r in records]

    idf = compute_idf(texts, tokenize)
    save_idf(idf, idf_path)

    vectors, elapsed = embed_texts(texts, idf=idf)

    index = VectorIndex(dim=EMBEDDING_DIM)
    index.add(vectors, records)
    index.save(index_path)

    print(f"Built KB index: {len(records)} entries "
          f"({sum(1 for r in records if r['standard']=='OWASP')} OWASP + "
          f"{sum(1 for r in records if r['standard']=='CWE')} CWE) "
          f"in {elapsed:.3f}s, saved to {index_path}.* (IDF vocab: {len(idf)} tokens -> {idf_path})")
    return index, idf


def load_knowledge_base(
    index_path: str = _DEFAULT_INDEX_PATH, idf_path: str = _DEFAULT_IDF_PATH
) -> tuple[VectorIndex, dict]:
    if not os.path.exists(f"{index_path}.faiss") or not os.path.exists(idf_path):
        return build_knowledge_base(index_path, idf_path)
    return VectorIndex.load(index_path), load_idf(idf_path)


if __name__ == "__main__":
    idx, idf = build_knowledge_base()

    def check(snippet: str, expected: str):
        query_vec, _ = embed_texts([snippet], idf=idf)
        hits = idx.search(query_vec[0], top_k=3)
        labels = [h.get("cwe_id", h.get("code")) for h in hits]
        mark = "OK " if labels and labels[0] == expected else "MISS"
        print(f"  [{mark}] expected {expected:10s} got top-3={labels}   ({snippet[:60]}...)")

    print("\nSanity checks (IDF-weighted):")
    check("cursor.execute(\"SELECT * FROM users WHERE name = '\" + name + \"'\")", "CWE-89")
    check("os.system('ping ' + hostname)", "CWE-78")
    check("open(base_dir + '/' + request.args['file'])", "CWE-22")
    check("pickle.loads(request.data)", "CWE-502")
