"""Tests for the LLM layer (providers, parsing, cache, analyzer) against a local mock server."""
import json
import os

import pytest

from mock_llm_server import MockLLMServer
from rag_vuln_detect.llm import providers
from rag_vuln_detect.llm.analyzer import (SecurityAnalyzer, VerdictCache, build_prompt, extract_json,
                                          normalise_cwe, parse_verdict)
from rag_vuln_detect.llm.providers import (GeminiProvider, GroqProvider, LLMAuthError, LLMError,
                                           OpenAICompatProvider, make_provider)

VULN = "def f(uid):\n    cursor.execute(\"SELECT * FROM users WHERE id = \" + uid)\n"
SAFE = "def f(uid):\n    return uid + 1\n"


@pytest.fixture()
def server():
    s = MockLLMServer().start()
    yield s
    s.stop()


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(providers.time, "sleep", lambda s: None)


def oa(server, **kw):
    return OpenAICompatProvider("k", kw.get("model"), server.openai_base, 100000)


# ---------------------------------------------------------------- parsing

def test_extract_json_plain_fenced_and_embedded():
    assert extract_json('{"a": 1}') == {"a": 1}
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('Sure! Here you go: {"a": {"b": "}"}} thanks') == {"a": {"b": "}"}}


def test_extract_json_rejects_garbage():
    for bad in ("", "no json here", "{unterminated", "[1,2]"):
        with pytest.raises(Exception):
            extract_json(bad)


@pytest.mark.parametrize("raw,exp", [("CWE-89", "CWE-89"), ("cwe 79", "CWE-79"), (22, "CWE-22"),
                                     ("CWE-089", "CWE-89"), (None, None), ("null", None), ("none", None), ("", None)])
def test_normalise_cwe(raw, exp):
    assert normalise_cwe(raw) == exp


def test_parse_verdict_vulnerable_and_safe():
    v = parse_verdict(json.dumps({"vulnerable": True, "cwe_id": "cwe-89", "confidence": 1.7,
                                  "explanation": "x", "fixed_code": "y"}))
    assert (v.status, v.vulnerable, v.cwe_id, v.confidence, v.fixed_code) == ("ok", True, "CWE-89", 1.0, "y")
    s = parse_verdict('{"vulnerable": "false", "cwe_id": "CWE-89", "fixed_code": "z"}')
    assert s.vulnerable is False and s.cwe_id is None and s.fixed_code == ""  # safe chunks carry no CWE/fix


def test_parse_verdict_requires_boolean():
    with pytest.raises(ValueError):
        parse_verdict('{"cwe_id": "CWE-89"}')


def test_build_prompt_includes_context_and_rubric():
    kb = [{"cwe_id": "CWE-89", "name": "SQL Injection", "description": "desc"}]
    system, user = build_prompt(VULN, file_path="a.py", language="python", kb_hits=kb,
                                repo_context=[{"path": "b.py", "name": "g", "lines": "1-2", "code": "x=1"}])
    assert "CWE-89" in user and "Vulnerable when" in user and "b.py" in user and "JSON" in system
    _, plain = build_prompt(VULN, file_path="a.py", language="python", kb_hits=None, repo_context=None)
    assert "RETRIEVED" not in plain


# -------------------------------------------------------------- providers

def test_openai_complete_and_model_discovery(server):
    p = oa(server)
    assert p.model == "mock-model"          # whisper-* filtered out, discovered at runtime
    out = json.loads(p.complete("sys", "CODE CHUNK:\n" + VULN))
    assert out["vulnerable"] is True
    post = [r for r in server.requests if r["method"] == "POST"][0]
    assert post["headers"]["Authorization"] == "Bearer k"
    assert post["payload"]["temperature"] == 0


def test_gemini_complete_uses_header_key_and_discovers_model(server):
    p = GeminiProvider("gkey", None, server.gemini_base, 100000)
    assert p.model == "mock-model"
    out = json.loads(p.complete("sys", "CODE CHUNK:\n" + VULN))
    assert out["cwe_id"] == "CWE-89"
    assert all("key=" not in r["path"] for r in server.requests)   # key never in the URL
    hdrs = {k.lower(): v for k, v in server.requests[-1]["headers"].items()}
    assert hdrs["x-goog-api-key"] == "gkey"


def test_retry_on_429_and_5xx_then_success(server):
    server.faults = [429, 503, 500]
    p = oa(server, model="mock-model")
    assert json.loads(p.complete("s", "CODE CHUNK:\n" + SAFE))["vulnerable"] is False
    assert len([r for r in server.requests if r["method"] == "POST"]) == 4


def test_auth_error_not_retried(server):
    server.faults = [401, 401, 401]
    with pytest.raises(LLMAuthError):
        oa(server, model="mock-model").complete("s", "u")
    assert len(server.requests) == 1


def test_retries_exhausted_raises(server):
    server.faults = [503] * 10
    with pytest.raises(LLMError):
        oa(server, model="mock-model").complete("s", "u")


def test_json_mode_rejected_falls_back(server):
    server.faults = [(400, "response_format json_object is not supported by this model")]
    out = oa(server, model="mock-model").complete("s", "CODE CHUNK:\n" + SAFE)
    assert json.loads(out)["vulnerable"] is False
    posts = [r for r in server.requests if r["method"] == "POST"]
    assert "response_format" in posts[0]["payload"] and "response_format" not in posts[1]["payload"]


def test_other_400_is_not_retried(server):
    server.faults = [(400, "context length exceeded")]
    with pytest.raises(LLMError):
        oa(server, model="mock-model").complete("s", "u")
    assert len(server.requests) == 1


def test_unexpected_shape_raises(server):
    server.faults = [b'{"weird": true}']
    with pytest.raises(LLMError):
        oa(server, model="mock-model").complete("s", "u")


def test_rate_limiter_spaces_calls(monkeypatch):
    slept = []
    t = {"now": 100.0}
    monkeypatch.setattr(providers.time, "monotonic", lambda: t["now"])
    monkeypatch.setattr(providers.time, "sleep", lambda s: slept.append(s))
    rl = providers.RateLimiter(60)   # 1 per second
    rl.wait(); rl.wait(); rl.wait()
    assert slept == [pytest.approx(1.0), pytest.approx(2.0)]


# ---------------------------------------------------------------- factory

def clean_env(monkeypatch):
    for k in ("LLM_PROVIDER", "LLM_MODEL", "LLM_RPM", "LLM_BASE_URL", "LLM_API_KEY", "GROQ_API_KEY",
              "GEMINI_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(providers, "load_dotenv", lambda path=None: None)


def test_make_provider_none_without_keys(monkeypatch):
    clean_env(monkeypatch)
    assert make_provider() is None


def test_make_provider_auto_selection(monkeypatch):
    clean_env(monkeypatch)
    monkeypatch.setenv("GROQ_API_KEY", "g")
    assert isinstance(make_provider(), GroqProvider)
    clean_env(monkeypatch)
    monkeypatch.setenv("GEMINI_API_KEY", "g")
    assert isinstance(make_provider(), GeminiProvider)
    clean_env(monkeypatch)
    monkeypatch.setenv("LLM_BASE_URL", "http://x/v1")
    assert isinstance(make_provider(), OpenAICompatProvider)
    clean_env(monkeypatch)
    monkeypatch.setenv("LLM_PROVIDER", "bogus")
    with pytest.raises(LLMError):
        make_provider()


def test_dotenv_does_not_override(tmp_path, monkeypatch):
    f = tmp_path / ".env"
    f.write_text('# c\nZZ_A="1"\nZZ_B=2\n\nbad line\n')
    monkeypatch.setenv("ZZ_B", "real")
    monkeypatch.delenv("ZZ_A", raising=False)
    providers.load_dotenv(str(f))
    assert os.environ["ZZ_A"] == "1" and os.environ["ZZ_B"] == "real"
    monkeypatch.delenv("ZZ_A", raising=False)


# --------------------------------------------------------------- analyzer

def analyzer(server, tmp_path, mode="auto"):
    return SecurityAnalyzer(oa(server, model="mock-model"), mode=mode,
                            cache=VerdictCache(str(tmp_path / "c.jsonl")))


def test_analyzer_verdict_and_cache_roundtrip(server, tmp_path):
    a = analyzer(server, tmp_path)
    v1 = a.analyze(VULN, file_path="a.py", language="python")
    assert v1.status == "ok" and v1.vulnerable and v1.cwe_id == "CWE-89" and not v1.cached
    n = len(server.requests)
    v2 = a.analyze(VULN, file_path="a.py", language="python")
    assert v2.cached and v2.cwe_id == "CWE-89" and len(server.requests) == n
    # a new analyzer on the same cache file (fresh process) hits too
    b = SecurityAnalyzer(None, mode="replay", cache=VerdictCache(str(tmp_path / "c.jsonl")))
    assert b.analyze(VULN).cached


def test_cache_key_separates_rag_modes(server, tmp_path):
    a = analyzer(server, tmp_path)
    a.analyze(VULN, kb_hits=[{"cwe_id": "CWE-89"}], use_rag=True)
    a.analyze(VULN, kb_hits=[{"cwe_id": "CWE-89"}], use_rag=False)
    assert a.stats["calls"] == 2


def test_replay_mode_never_calls_and_reports_miss(server, tmp_path):
    a = SecurityAnalyzer(oa(server, model="mock-model"), mode="replay",
                         cache=VerdictCache(str(tmp_path / "c.jsonl")))
    v = a.analyze(VULN)
    assert v.status == "not_cached" and not server.requests


def test_live_mode_bypasses_cache(server, tmp_path):
    a = analyzer(server, tmp_path, "live")
    a.analyze(VULN); a.analyze(VULN)
    assert a.stats["calls"] == 2 and a.stats["cache_hits"] == 0


def test_no_provider_is_unavailable_not_crash(tmp_path):
    a = SecurityAnalyzer(None, mode="auto", cache=VerdictCache(str(tmp_path / "c.jsonl")))
    assert not a.available
    v = a.analyze(VULN)
    assert v.status == "unavailable" and v.vulnerable is None


def test_bad_json_retried_once_then_error(server, tmp_path):
    server.reply_override = lambda u: "I think it is vulnerable, sorry"
    v = analyzer(server, tmp_path).analyze(VULN)
    assert v.status == "error" and "unparseable" in v.error
    assert len([r for r in server.requests if r["method"] == "POST"]) == 2


def test_bad_json_then_good_recovers(server, tmp_path):
    seq = iter(["nope", json.dumps({"vulnerable": False, "confidence": 0.7})])
    server.reply_override = lambda u: next(seq)
    v = analyzer(server, tmp_path).analyze(SAFE)
    assert v.status == "ok" and v.vulnerable is False


def test_auth_failure_becomes_error_verdict(server, tmp_path):
    server.faults = [401]
    v = analyzer(server, tmp_path).analyze(VULN)
    assert v.status == "error" and "API key" in v.error


def test_error_verdicts_are_not_cached(server, tmp_path):
    server.faults = [401]
    a = analyzer(server, tmp_path)
    a.analyze(VULN)
    assert len(a.cache) == 0
    assert a.analyze(VULN).status == "ok"


def test_429_slows_the_rate_limiter(server):
    server.faults = [429, 429]
    p = oa(server, model="mock-model")
    before = p.limiter.interval
    p.complete("s", "CODE CHUNK:\n" + SAFE)
    assert p.limiter.interval == pytest.approx(before * 1.5 * 1.5)
    p.limiter.slow_down(factor=1e9)
    assert p.limiter.interval == 30.0            # capped


# ------------------------------------------------ model ranking / retired models

def test_gemini_ranks_newest_stable_flash_first_and_skips_junk():
    p = GeminiProvider("k", None, "http://x", 100000)
    ranked = p.rank_models([
        "gemini-2.5-flash", "gemini-3.8-flash", "gemini-3.8-flash-lite", "gemini-3.8-pro", "gemini-3.9-flash-preview",
        "gemini-2.5-flash-image", "gemini-2.5-flash-preview-tts", "gemma-3-27b-it", "embedding-001", "gemini-live-2.5-flash"])
    assert ranked[0] == "gemini-3.8-flash"
    assert ranked.index("gemini-2.5-flash") < ranked.index("gemini-3.8-flash-lite")   # flash before flash-lite
    assert ranked[-1] == "gemini-3.9-flash-preview"                                   # unstable models last
    assert not any(x in " ".join(ranked) for x in ("image", "tts", "gemma", "embedding", "live"))


def test_retired_model_triggers_automatic_fallback(server):
    server.extra_models = ["gemini-2.5-flash"]
    server.model = "gemini-3.8-flash"
    server.retired = {"gemini-3.8-flash"}                      # newest is rejected -> next best is used
    p = GeminiProvider("k", None, server.gemini_base, 100000)
    out = json.loads(p.complete("s", "CODE CHUNK:\n" + SAFE))
    assert out["vulnerable"] is False and p.model == "gemini-2.5-flash"
    posts = [r["path"] for r in server.requests if r["method"] == "POST"]
    assert "gemini-3.8-flash" in posts[0] and "gemini-2.5-flash" in posts[1]


def test_pinned_model_is_never_switched(server):
    server.retired = {"mock-model"}
    p = GeminiProvider("k", "mock-model", server.gemini_base, 100000)    # explicit LLM_MODEL
    with pytest.raises(LLMError, match="404"):
        p.complete("s", "u")
    assert len([r for r in server.requests if r["method"] == "POST"]) == 1


def test_all_models_retired_raises_instead_of_looping(server):
    server.extra_models = ["gemini-2.5-flash"]; server.model = "gemini-3.8-flash"
    server.retired = {"gemini-3.8-flash", "gemini-2.5-flash"}
    p = GeminiProvider("k", None, server.gemini_base, 100000)
    with pytest.raises(LLMError, match="404"):
        p.complete("s", "u")


def test_groq_style_fallback_on_openai_endpoint(server):
    server.extra_models = ["llama-3.3-70b-versatile"]
    server.retired = {"mock-model"}
    p = GroqProvider("k", None, server.openai_base, 100000)      # prefers llama-3.3-70b-versatile anyway
    assert p.model == "llama-3.3-70b-versatile"
    assert json.loads(p.complete("s", "CODE CHUNK:\n" + SAFE))["vulnerable"] is False


# ------------------------------------------------ daily quota exhausted (free tier)

def test_daily_quota_429_fails_fast_and_switches_model(server):
    server.extra_models = ["gemini-2.5-flash"]; server.model = "gemini-3.8-flash"
    server.exhausted = {"gemini-3.8-flash"}
    p = GeminiProvider("k", None, server.gemini_base, 100000)
    out = json.loads(p.complete("s", "CODE CHUNK:\n" + SAFE))
    assert out["vulnerable"] is False and p.model == "gemini-2.5-flash"
    posts = [r["path"] for r in server.requests if r["method"] == "POST"]
    assert len(posts) == 2                       # no 6-try backoff on a quota that resets in hours


def test_daily_quota_on_every_model_raises_quickly(server):
    server.extra_models = ["gemini-2.5-flash"]; server.model = "gemini-3.8-flash"
    server.exhausted = {"gemini-3.8-flash", "gemini-2.5-flash"}
    p = GeminiProvider("k", None, server.gemini_base, 100000)
    with pytest.raises(LLMError, match="daily quota"):
        p.complete("s", "u")


def test_per_minute_429_is_still_retried(server):
    server.faults = [429, 429]
    p = oa(server, model="mock-model")
    assert json.loads(p.complete("s", "CODE CHUNK:\n" + SAFE))["vulnerable"] is False


# ------------------------------------------------ retry hints / limiter recovery (Groq per-minute limits)

@pytest.mark.parametrize("body,exp", [
    ("Please try again in 6.5s.", 6.5),
    ("Please try again in 1m3.2s.", 63.2),
    ("try again in 800ms", 0.8),
    ("nothing useful here", 0.0),
])
def test_retry_hint_parses_provider_wait_times(body, exp):
    assert providers._retry_hint({}, body) == pytest.approx(exp)


def test_retry_hint_prefers_retry_after_header():
    assert providers._retry_hint({"Retry-After": "7"}, "try again in 30s") == pytest.approx(7.0)


def test_rate_limiter_recovers_after_a_success_streak_but_never_beats_its_base():
    rl = providers.RateLimiter(60)               # base interval 1 s
    rl.slow_down(); rl.slow_down()
    slowed = rl.interval
    assert slowed > rl.base
    for _ in range(40):
        rl.speed_up()
    assert rl.base <= rl.interval < slowed
    assert rl.interval == pytest.approx(rl.base)


# ------------------------------------------------ token accounting

def test_provider_records_tokens_per_model_openai_and_gemini(server):
    p = oa(server, model="mock-model")
    p.complete("s", "CODE CHUNK:\n" + SAFE); p.complete("s", "CODE CHUNK:\n" + SAFE)
    assert p.usage["prompt"] == 2000 and p.usage["completion"] == 400
    assert p.usage["by_model"]["mock-model"] == {"calls": 2, "tokens": 2400}
    g = GeminiProvider("k", "mock-model", server.gemini_base, 100000)
    g.complete("s", "CODE CHUNK:\n" + SAFE)
    assert g.usage["prompt"] == 900 and g.usage["completion"] == 100
