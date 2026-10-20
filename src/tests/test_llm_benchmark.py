"""The LLM benchmark script, exercised end to end against the mock server (plumbing only)."""
import importlib.util
import json
import os
import sys

import pytest

from mock_llm_server import MockLLMServer
from rag_vuln_detect.llm import providers

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def load_script():
    spec = importlib.util.spec_from_file_location("run_llm_benchmark", os.path.join(ROOT, "evaluation", "run_llm_benchmark.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_wilson_interval():
    m = load_script()
    lo, hi = m.wilson(30, 60)
    assert 0.37 < lo < 0.38 and 0.62 < hi < 0.63
    assert m.wilson(0, 0) == (0.0, 0.0)


def test_pairs_cover_both_splits_and_have_patched_versions():
    m = load_script()
    pairs = m.load_pairs()
    assert len(pairs) == 161 and {p["split"] for p in pairs} == {"dev", "heldout", "extended", "heldout2"}
    assert all(p["patched"].strip() and p["patched"] != p["vulnerable"] for p in pairs)
    assert {p["split"] for p in m.load_pairs(limit=10)} == {"dev", "heldout", "extended", "heldout2"}


def test_script_runs_and_writes_results(tmp_path, monkeypatch):
    srv = MockLLMServer().start()
    try:
        for k in ("GROQ_API_KEY", "GEMINI_API_KEY"):
            monkeypatch.delenv(k, raising=False)
        monkeypatch.setattr(providers, "load_dotenv", lambda path=None: None)
        monkeypatch.setenv("LLM_PROVIDER", "openai"); monkeypatch.setenv("LLM_BASE_URL", srv.openai_base)
        monkeypatch.setenv("LLM_MODEL", "mock-model"); monkeypatch.setenv("LLM_RPM", "100000")
        m = load_script()
        monkeypatch.setattr(sys, "argv", ["x", "--limit", "6", "--out-dir", str(tmp_path)])
        assert m.main() == 0
    finally:
        srv.stop()
    out = json.loads((tmp_path / "llm_benchmark.json").read_text())
    assert out["n_pairs"] == 6 and out["model"] == "mock-model"
    assert set(out["configs"]) == {"llm-only", "llm+rag", "retrieval-only (no verdict step)"}
    base = out["configs"]["retrieval-only (no verdict step)"]
    assert base["pair_accuracy"] == 0.0 and base["false_positive_rate"] == 1.0
    for k in ("llm-only", "llm+rag"):
        c = out["configs"][k]
        assert c["n_pairs"] == 6 and 0 <= c["pair_accuracy"] <= 1 and len(c["pair_accuracy_ci95"]) == 2
    assert out["paired_comparison"]["pairs_compared"] == 6
    assert (tmp_path / "llm_benchmark_items.csv").read_text().count("\n") == 1 + 12


def test_script_without_key_exits_cleanly(monkeypatch, capsys, tmp_path):
    for k in ("GROQ_API_KEY", "GEMINI_API_KEY", "LLM_PROVIDER", "LLM_BASE_URL"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(providers, "load_dotenv", lambda path=None: None)
    m = load_script()
    monkeypatch.setattr(sys, "argv", ["x", "--out-dir", str(tmp_path)])
    assert m.main() == 2 and "No LLM configured" in capsys.readouterr().out
