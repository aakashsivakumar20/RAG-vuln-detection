"""
Minimal automated test suite for the Review 3 modules. Run with:
    cd src && python -m pytest tests/ -v
"""
import math
import os
import sys
import tempfile

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rag_vuln_detect.chunking.chunker import chunk_file
from rag_vuln_detect.embeddings.embedder import embed_texts, tokenize
from rag_vuln_detect.vectorstore.faiss_store import VectorIndex
from rag_vuln_detect.knowledge_base.build_kb import load_knowledge_base


def _write_temp(content: str, suffix: str) -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


def test_python_chunker_finds_function_and_class():
    src = (
        "class Foo:\n"
        "    def bar(self):\n"
        "        return 1\n"
        "\n"
        "def standalone():\n"
        "    return 2\n"
    )
    path = _write_temp(src, ".py")
    chunks = chunk_file(path, "sample.py", "python")
    kinds = sorted(c.kind for c in chunks)
    names = sorted(c.name for c in chunks)
    assert kinds == ["class", "function"]
    assert names == ["Foo", "standalone"]


def test_javascript_chunker_finds_function_declaration():
    src = "function greet(name) {\n  return 'hi ' + name;\n}\n"
    path = _write_temp(src, ".js")
    chunks = chunk_file(path, "sample.js", "javascript")
    assert len(chunks) == 1
    assert chunks[0].name == "greet"
    assert chunks[0].kind == "function"


def test_tokenize_splits_camel_and_snake_case():
    assert tokenize("getUserName") == ["get", "user", "name"]
    assert tokenize("get_user_name") == ["get", "user", "name"]


def test_embeddings_are_unit_normalised():
    vecs, _ = embed_texts(["def add(a, b): return a + b", "SELECT * FROM t"])
    norms = np.linalg.norm(vecs, axis=1)
    for n in norms:
        assert math.isclose(n, 1.0, abs_tol=1e-4) or n == 0.0


def test_vector_index_save_and_load_roundtrip(tmp_path):
    from rag_vuln_detect.embeddings.embedder import EMBEDDING_DIM
    idx = VectorIndex(dim=EMBEDDING_DIM)
    vecs, _ = embed_texts(["alpha function", "beta function"])
    idx.add(vecs, [{"label": "alpha"}, {"label": "beta"}])
    prefix = str(tmp_path / "idx")
    idx.save(prefix)

    loaded = VectorIndex.load(prefix)
    assert len(loaded) == 2
    results = loaded.search(vecs[0], top_k=1)
    assert results[0]["label"] == "alpha"


def test_knowledge_base_loads_35_entries():
    kb_index, idf = load_knowledge_base()
    assert len(kb_index) == 35
    assert isinstance(idf, dict) and len(idf) > 0


def test_knowledge_base_retrieves_sql_injection_top1():
    kb_index, idf = load_knowledge_base()
    vec, _ = embed_texts(
        ["cursor.execute(\"SELECT * FROM users WHERE name = '\" + name + \"'\")"], idf=idf
    )
    hits = kb_index.search(vec[0], top_k=1)
    assert hits[0]["cwe_id"] == "CWE-89"
