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
    assert len(kb_index) == 269
    assert isinstance(idf, dict) and len(idf) > 0


def test_knowledge_base_retrieves_sql_injection_top1():
    kb_index, idf = load_knowledge_base()
    vec, _ = embed_texts(
        ["cursor.execute(\"SELECT * FROM users WHERE name = '\" + name + \"'\")"], idf=idf
    )
    hits = kb_index.search(vec[0], top_k=1)
    assert hits[0]["cwe_id"] == "CWE-89"


def test_extended_kb_integrity():
    """The extended catalogue loads, has unique ids, valid OWASP categories and severity entries, and every
    evaluation snippet label exists in the knowledge base."""
    import json
    import os
    from rag_vuln_detect.knowledge_base.build_kb import load_kb_records
    from rag_vuln_detect.llm.analyzer import load_rubrics
    from rag_vuln_detect.retrieval.hybrid import load_signals
    from rag_vuln_detect.severity.scorer import BASE_SEVERITY, OWASP_CATEGORY_SEVERITY

    recs = load_kb_records()
    ids = [r.get("cwe_id") or r.get("code") for r in recs]
    assert len(ids) == len(set(ids)) >= 260
    ext = [r for r in recs if r.get("tier") == "extended"]
    assert len(ext) >= 230
    signals = load_signals()
    for r in ext:
        assert r["owasp_category"] in OWASP_CATEGORY_SEVERITY, r["cwe_id"]
        assert r["cwe_id"] in BASE_SEVERITY and r["cwe_id"] in signals, r["cwe_id"]
        assert len(r["description"]) > 40 and r["name"]
    rubrics = load_rubrics()
    assert sum(1 for r in recs if r.get("cwe_id") in rubrics) >= 80
    here = os.path.dirname(os.path.abspath(__file__))
    for fname in ("benchmark_snippets.json", "heldout_snippets.json", "extended_snippets.json", "heldout2_snippets.json"):
        with open(os.path.join(here, "..", "..", "evaluation", fname)) as f:
            for s in json.load(f)["snippets"]:
                assert s["expected_cwe"] in ids, (fname, s["id"])


def test_sink_rules_load_compile_and_point_at_real_cwes():
    import re
    from rag_vuln_detect.knowledge_base.build_kb import load_kb_records
    from rag_vuln_detect.retrieval import patterns
    ids = {r.get("cwe_id") for r in load_kb_records()}
    rules = patterns.load_rules()
    assert len(rules) >= 150
    assert len({r.id for r in rules}) == len(rules), "duplicate rule ids"
    for r in rules:
        assert r.cwe in ids, (r.id, r.cwe)
        assert 0.0 < r.weight <= 1.0, r.id
        assert r.note, f"rule {r.id} has no note"


def test_sink_rules_fire_on_vulnerable_and_respect_unless():
    from rag_vuln_detect.retrieval import patterns
    rules = patterns.load_rules()
    def cwes(code, lang):
        return patterns.cwe_scores(patterns.scan(code, lang, rules))
    assert cwes('os.system("ping -c 1 " + host)', "python").get("CWE-78", 0) >= 0.8
    assert cwes("db.execute(\"SELECT * FROM t WHERE a = '\" + x + \"'\")", "python").get("CWE-89", 0) >= 0.8
    assert cwes("el.innerHTML = comment.text;", "javascript").get("CWE-79", 0) >= 0.7
    assert cwes("requests.get(u, verify=False)", "python").get("CWE-295", 0) >= 0.9
    # a comment mentioning a dangerous API must not fire
    assert "CWE-78" not in cwes("# never call os.system(cmd) here\nreturn 1", "python")
    # language filter: a JS-only rule does not fire on Python
    assert "CWE-79" not in cwes("el.innerHTML = x", "python") or cwes("el.innerHTML = x", "python")["CWE-79"] < 0.7
    # 'unless' cancels: yaml.safe_load is fine
    assert cwes("yaml.safe_load(raw)", "python").get("CWE-502", 0) == 0


def test_retriever_exposes_components_and_rule_hits():
    from rag_vuln_detect.knowledge_base.build_kb import load_knowledge_base
    from rag_vuln_detect.retrieval.hybrid import HybridRetriever, record_id
    kb, idf = load_knowledge_base()
    r = HybridRetriever(kb, idf)
    c = r.components("def f(h):\n    os.system('ping ' + h)", "python")
    assert set(c) >= {"dense", "lexical", "dense_norm", "lexical_norm", "pattern", "fused", "hits"}
    assert len(c["fused"]) == len(kb)
    assert any(h.rule.cwe == "CWE-78" for h in c["hits"])
    top = r.search("def f(h):\n    os.system('ping ' + h)", top_k=3, language="python")
    assert record_id(top[0]) in ("CWE-78", "CWE-77") and top[0]["pattern_score"] > 0
