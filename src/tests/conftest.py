import os
import sys
import tempfile

import pytest

_SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TESTS = os.path.dirname(os.path.abspath(__file__))
for p in (_SRC, _TESTS):
    if p not in sys.path:
        sys.path.insert(0, p)


@pytest.fixture(autouse=True)
def _isolate_llm_cache(monkeypatch, tmp_path_factory):
    """No test may read or write the project's real data/llm_cache.jsonl or read a real .env key."""
    monkeypatch.setenv("RAGVULN_LLM_CACHE", os.path.join(tempfile.mkdtemp(prefix="llmcache_"), "cache.jsonl"))
