"""End-to-end tests of the scan pipeline (ingestion -> ... -> findings store) with a local mock LLM."""
import os
import shutil
import zipfile

import pytest

from mock_llm_server import MockLLMServer
from rag_vuln_detect.findings_store import store
from rag_vuln_detect.llm import providers
from rag_vuln_detect.llm.analyzer import SecurityAnalyzer, VerdictCache
from rag_vuln_detect.llm.providers import OpenAICompatProvider
from rag_vuln_detect.pipeline.scan import ScanConfig, run_scan

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEMO = os.path.join(ROOT, "demo", "vulnerable_demo_app")


@pytest.fixture()
def server():
    s = MockLLMServer().start()
    yield s
    s.stop()


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(providers.time, "sleep", lambda s: None)


@pytest.fixture()
def db(tmp_path):
    return str(tmp_path / "f.db")


def make_analyzer(server, tmp_path, mode="auto"):
    return SecurityAnalyzer(OpenAICompatProvider("k", "mock-model", server.openai_base, 100000), mode=mode,
                            cache=VerdictCache(str(tmp_path / "cache.jsonl")))


def test_end_to_end_with_llm(server, tmp_path, db):
    an = make_analyzer(server, tmp_path)
    stages = []
    res = run_scan(DEMO, ScanConfig(), analyzer=an, db_path=db, progress=lambda s, f, m: stages.append(s))
    c = res["counts"]
    assert res["mode"] == "llm-rag" and res["warning"] is None
    assert c["confirmed"] + c["needs_review"] + c["rejected"] + c["unverified"] == c["chunks_analysed"] == 38
    assert c["llm_calls"] == 38 and c["unverified"] == 0
    assert c["llm_tokens_in"] == 38 * 1000 and c["llm_tokens_out"] == 38 * 200 and c["llm_models_used"] == {"mock-model": 38}
    assert list(dict.fromkeys(stages)) == ["ingestion", "chunking", "embedding", "retrieval", "triage", "analysis", "done"]
    scan = store.get_scan(res["scan_id"], db_path=db)
    assert scan["status"] == "done" and scan["progress"] == 1.0 and scan["model"] == "mock-model"
    confirmed = store.query_findings(scan_id=res["scan_id"], status="confirmed", db_path=db)
    assert confirmed, "mock flags at least the obvious SQLi / command injection"
    sqli = [f for f in confirmed if f.cwe_id == "CWE-89"][0]
    assert sqli.severity_band == "Critical" and sqli.remediation["template"]["cwe_id"] == "CWE-89"
    assert sqli.remediation["llm"]["after"] and sqli.code and sqli.retrieved_kb_context[0]["id"]
    assert sqli.llm_model.endswith("mock-model")
    rejected = store.query_findings(scan_id=res["scan_id"], status="rejected", db_path=db)
    assert rejected and all(f.severity_band == "None" and f.remediation is None for f in rejected)


def test_retrieval_only_mode_is_marked_unverified(tmp_path, db):
    an = SecurityAnalyzer(None, mode="live", cache=VerdictCache(str(tmp_path / "c.jsonl")))
    res = run_scan(DEMO, ScanConfig(max_candidates_no_llm=10), analyzer=an, db_path=db)
    assert res["mode"] == "retrieval-only" and "No LLM configured" in res["warning"]
    rows = store.query_findings(scan_id=res["scan_id"], db_path=db)
    assert len(rows) == 10 and all(f.status == "unverified" for f in rows)
    assert all("UNVERIFIED" in f.rationale and f.llm_vulnerable is None for f in rows)
    cwes = {f.cwe_id for f in rows}
    assert {"CWE-89", "CWE-22"} & cwes          # retrieval alone surfaces the obvious weakness classes


def test_llm_budget_limits_calls(server, tmp_path, db):
    an = make_analyzer(server, tmp_path)
    res = run_scan(DEMO, ScanConfig(max_llm_chunks=5), analyzer=an, db_path=db)
    assert res["counts"]["llm_calls"] == 5 and res["counts"]["chunks_analysed"] == 5
    assert res["counts"]["chunks_not_analysed_budget"] == 33          # 38 non-trivial units - 5 analysed
    assert len(store.query_findings(scan_id=res["scan_id"], db_path=db)) == 5


def test_bad_api_key_stops_llm_and_degrades_to_unverified(server, tmp_path, db):
    server.faults = [401] * 50
    an = make_analyzer(server, tmp_path)
    res = run_scan(DEMO, ScanConfig(max_llm_chunks=8, llm_workers=1), analyzer=an, db_path=db)
    assert res["counts"]["llm_calls"] == 1                         # no hammering a rejected key
    assert "LLM analysis stopped" in res["warning"] and "API key" in res["warning"]
    rows = store.query_findings(scan_id=res["scan_id"], db_path=db)
    assert len(rows) == 8 and all(f.status == "unverified" for f in rows)
    assert store.get_scan(res["scan_id"], db_path=db)["status"] == "done"


def test_transient_errors_do_not_kill_the_scan(server, tmp_path, db):
    server.faults = [(400, "context length exceeded")] * 2          # two chunks fail, rest succeed
    an = make_analyzer(server, tmp_path)
    res = run_scan(DEMO, ScanConfig(max_llm_chunks=6), analyzer=an, db_path=db)
    c = res["counts"]
    assert c["llm_errors"] == 2 and c["unverified"] == 2 and c["confirmed"] + c["rejected"] + c["needs_review"] == 4
    assert "2 LLM request(s) failed" in res["warning"]


def test_replay_mode_reuses_cached_verdicts_offline(server, tmp_path, db):
    run_scan(DEMO, ScanConfig(max_llm_chunks=6), analyzer=make_analyzer(server, tmp_path), db_path=db)
    offline = SecurityAnalyzer(None, mode="replay", cache=VerdictCache(str(tmp_path / "cache.jsonl")))
    n = len(server.requests)
    res = run_scan(DEMO, ScanConfig(max_llm_chunks=6, llm_mode="replay"), analyzer=offline, db_path=db)
    assert len(server.requests) == n and res["counts"]["llm_calls"] == 0
    assert res["counts"]["llm_cache_hits"] == 6 and res["counts"]["unverified"] == 0 and res["mode"] == "llm-rag"


def test_llm_only_ablation_sends_no_retrieved_context(server, tmp_path, db):
    run_scan(DEMO, ScanConfig(max_llm_chunks=3, use_rag=False), analyzer=make_analyzer(server, tmp_path), db_path=db)
    prompts = [r["payload"]["messages"][-1]["content"] for r in server.requests if r["method"] == "POST"]
    assert prompts and all("RETRIEVED SECURITY KNOWLEDGE" not in p and "SIMILAR CODE" not in p for p in prompts)
    server.requests.clear()
    run_scan(DEMO, ScanConfig(max_llm_chunks=3, use_rag=True), analyzer=make_analyzer(server, tmp_path), db_path=db)
    prompts = [r["payload"]["messages"][-1]["content"] for r in server.requests if r["method"] == "POST"]
    assert all("RETRIEVED SECURITY KNOWLEDGE" in p and "SIMILAR CODE" in p for p in prompts)


def test_cancel_marks_scan_cancelled(server, tmp_path, db):
    calls = {"n": 0}

    def cancel():
        calls["n"] += 1
        return calls["n"] > 12

    res = run_scan(DEMO, ScanConfig(), analyzer=make_analyzer(server, tmp_path), db_path=db, should_cancel=cancel)
    assert res.get("cancelled") and store.get_scan(res["scan_id"], db_path=db)["status"] == "cancelled"


def test_missing_source_marks_scan_failed(tmp_path, db):
    an = SecurityAnalyzer(None, mode="live", cache=VerdictCache(str(tmp_path / "c.jsonl")))
    with pytest.raises(Exception):
        run_scan(str(tmp_path / "does-not-exist"), ScanConfig(), analyzer=an, db_path=db)
    s = store.list_scans(db_path=db)[0]
    assert s["status"] == "failed" and s["error"]


def test_no_source_files_is_a_clear_failure(tmp_path, db):
    (tmp_path / "proj").mkdir()
    (tmp_path / "proj" / "notes.txt").write_text("hello")
    an = SecurityAnalyzer(None, mode="live", cache=VerdictCache(str(tmp_path / "c.jsonl")))
    with pytest.raises(RuntimeError, match="no analysable source"):
        run_scan(str(tmp_path / "proj"), ScanConfig(), analyzer=an, db_path=db)


def test_zip_source(tmp_path, db):
    zpath = str(tmp_path / "demo.zip")
    with zipfile.ZipFile(zpath, "w") as zf:
        for dp, _, fs in os.walk(DEMO):
            for f in fs:
                p = os.path.join(dp, f)
                zf.write(p, os.path.join("demo-main", os.path.relpath(p, DEMO)))
    an = SecurityAnalyzer(None, mode="live", cache=VerdictCache(str(tmp_path / "c.jsonl")))
    res = run_scan(zpath, ScanConfig(max_candidates_no_llm=3), analyzer=an, db_path=db)
    assert res["counts"]["files_analysable"] == 10


def test_zip_slip_is_refused(tmp_path, db):
    zpath = str(tmp_path / "evil.zip")
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("../evil.py", "x = 1")
    an = SecurityAnalyzer(None, mode="live", cache=VerdictCache(str(tmp_path / "c.jsonl")))
    with pytest.raises(RuntimeError, match="unsafe path"):
        run_scan(zpath, ScanConfig(), analyzer=an, db_path=db)


def test_test_files_skipped_and_parent_folder_names_do_not_matter(tmp_path, db):
    proj = tmp_path / "build" / "env" / "proj"        # parents named like vendored dirs must not hide the project
    (proj / "tests").mkdir(parents=True)
    shutil.copy(os.path.join(DEMO, "app", "database.py"), proj / "database.py")
    shutil.copy(os.path.join(DEMO, "app", "database.py"), proj / "tests" / "test_db.py")
    an = SecurityAnalyzer(None, mode="live", cache=VerdictCache(str(tmp_path / "c.jsonl")))
    res = run_scan(str(proj), ScanConfig(), analyzer=an, db_path=db)
    assert res["counts"]["files_analysable"] == 2 and res["counts"]["files_skipped_tests"] == 1
    paths = {f.file_path for f in store.query_findings(scan_id=res["scan_id"], db_path=db)}
    assert paths == {"database.py"}


def test_parallel_workers_overlap_latency_and_match_sequential(server, tmp_path):
    import time
    server.latency = 0.12
    results = {}
    for workers in (1, 4):
        an = make_analyzer(server, tmp_path, mode="live")
        an.cache = VerdictCache(str(tmp_path / f"cache{workers}.jsonl"))
        t0 = time.time()
        res = run_scan(DEMO, ScanConfig(max_llm_chunks=16, llm_workers=workers), analyzer=an,
                       db_path=str(tmp_path / f"w{workers}.db"))
        results[workers] = (time.time() - t0, res["counts"], res["scan_id"], str(tmp_path / f"w{workers}.db"))
    (t1, c1, id1, db1), (t4, c4, id4, db4) = results[1], results[4]
    assert t4 < t1 * 0.7, f"4 workers ({t4:.2f}s) should clearly beat 1 worker ({t1:.2f}s)"
    for k in ("confirmed", "needs_review", "rejected", "unverified", "llm_errors", "chunks_analysed"):
        assert c1[k] == c4[k], k
    # same findings, stored in the same (priority) order
    seq = [(f.chunk_id, f.status) for f in store.query_findings(scan_id=id1, db_path=db1, order="newest")]
    par = [(f.chunk_id, f.status) for f in store.query_findings(scan_id=id4, db_path=db4, order="newest")]
    assert sorted(seq) == sorted(par) and len(seq) == 16


def test_parallel_workers_stop_after_auth_failure(server, tmp_path, db):
    server.faults = [401] * 200
    an = make_analyzer(server, tmp_path, mode="live")
    res = run_scan(DEMO, ScanConfig(max_llm_chunks=20, llm_workers=4), analyzer=an, db_path=db)
    assert res["warning"] and "LLM analysis stopped early" in res["warning"]
    assert res["counts"]["confirmed"] == 0 and res["counts"]["unverified"] == 20
    assert res["counts"]["llm_calls"] <= 4                         # at most the requests already in flight


# ----------------------------------------------------- instant triage + live in-place verification

def test_triage_rows_exist_before_first_llm_verdict_and_are_updated_in_place(server, tmp_path, db):
    an = make_analyzer(server, tmp_path)
    seen = {}

    def progress(stage, frac, msg):
        if stage == "analysis" and "snap" not in seen:
            seen["snap"] = store.count_by_status(db_path=db)

    res = run_scan(DEMO, ScanConfig(), analyzer=an, db_path=db, progress=progress)
    # when the analysis stage first reported, every candidate was already stored as a pending triage row
    assert seen["snap"].get("pending", 0) >= 30
    final = store.count_by_status(scan_id=res["scan_id"], db_path=db)
    assert "pending" not in final and sum(final.values()) == res["counts"]["chunks_analysed"] == 38
    assert res["counts"]["triage_ready_s"] < 30


def test_pending_rows_have_retrieval_severity_and_template_and_are_not_claimed_as_vulnerable(server, tmp_path, db):
    an = make_analyzer(server, tmp_path)
    snap = {}

    def progress(stage, frac, msg):
        if stage == "triage":
            snap["rows"] = store.query_findings(status="pending", db_path=db)

    run_scan(DEMO, ScanConfig(), analyzer=an, db_path=db, progress=progress)
    rows = snap["rows"]
    assert rows and all(r.llm_vulnerable is None and "UNVERIFIED" in r.rationale for r in rows)
    assert any(r.remediation and r.remediation.get("template") for r in rows)


def test_cancel_turns_pending_rows_into_unverified(server, tmp_path, db):
    an = make_analyzer(server, tmp_path)
    flag = {"stop": False}

    def progress(stage, frac, msg):
        if stage == "triage":
            flag["stop"] = True

    from rag_vuln_detect.pipeline.scan import ScanCancelled  # noqa: F401
    res = run_scan(DEMO, ScanConfig(), analyzer=an, db_path=db, progress=progress, should_cancel=lambda: flag["stop"])
    assert res.get("cancelled")
    st = store.count_by_status(scan_id=res["scan_id"], db_path=db)
    assert "pending" not in st and st.get("unverified", 0) >= 30
