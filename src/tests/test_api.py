"""API server tests: real HTTP against a local server instance with a mock LLM behind it."""
import json
import os
import threading
import time
import urllib.error
import urllib.request

import pytest

from mock_llm_server import MockLLMServer
from rag_vuln_detect.api import server as api
from rag_vuln_detect.llm import providers


@pytest.fixture()
def mock_llm():
    s = MockLLMServer().start()
    yield s
    s.stop()


@pytest.fixture()
def env(monkeypatch, mock_llm, tmp_path):
    for k in ("GROQ_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(providers, "load_dotenv", lambda path=None: None)
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("LLM_BASE_URL", mock_llm.openai_base)
    monkeypatch.setenv("LLM_MODEL", "mock-model")
    monkeypatch.setenv("LLM_RPM", "100000")
    monkeypatch.setattr(api, "PROJECT_ROOT", str(tmp_path))


@pytest.fixture()
def srv(env, tmp_path):
    s = api.create_server("127.0.0.1", 0, str(tmp_path / "api.db"))
    t = threading.Thread(target=lambda: s.serve_forever(poll_interval=0.02), daemon=True)
    t.start()
    s.base = f"http://127.0.0.1:{s.server_address[1]}"
    yield s
    s.shutdown()
    s.server_close()


def call(srv, method, path, body=None, headers=None, raw=False):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json"} if body is not None else {}
    h.update(headers or {})
    req = urllib.request.Request(srv.base + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            payload = r.read()
            return r.status, (payload if raw else json.loads(payload)), r.headers
    except urllib.error.HTTPError as e:
        payload = e.read()
        try:
            return e.code, json.loads(payload), e.headers
        except json.JSONDecodeError:
            return e.code, payload, e.headers


def wait_done(srv, sid, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        _, scan, _ = call(srv, "GET", f"/api/scans/{sid}")
        if scan["status"] != "running":
            return scan
        time.sleep(0.05)
    raise AssertionError("scan did not finish")


def test_health(srv):
    code, h, _ = call(srv, "GET", "/api/health")
    assert code == 200 and h["ok"] and h["kb_entries"] == 269
    assert h["llm"]["configured"] and h["llm"]["model"] == "mock-model"


def test_host_header_rejected(srv):
    code, body, _ = call(srv, "GET", "/api/health", headers={"Host": "evil.example.com"})
    assert code == 403


def test_writes_require_json_content_type(srv):
    req = urllib.request.Request(srv.base + "/api/scans", data=b'{"source":"demo"}', method="POST",
                                 headers={"Content-Type": "text/plain"})
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req)
    assert e.value.code == 415


def test_full_scan_flow_findings_detail_triage_export(srv):
    code, r, _ = call(srv, "POST", "/api/scans", {"source": "demo", "max_llm_chunks": 40})
    assert code == 202
    sid = r["scan_id"]
    scan = wait_done(srv, sid)
    assert scan["status"] == "done" and scan["progress"] == 1.0
    assert sum(scan["by_status"].values()) == scan["counts"]["chunks_analysed"]

    code, lst, _ = call(srv, "GET", f"/api/scans/{sid}/findings")
    assert code == 200 and lst["count"] >= 1
    assert all(f["status"] != "rejected" for f in lst["findings"])
    assert "code" not in lst["findings"][0]                      # list view is light
    _, rej, _ = call(srv, "GET", f"/api/scans/{sid}/findings?include_rejected=1")
    assert rej["count"] == scan["counts"]["chunks_analysed"]
    _, sev, _ = call(srv, "GET", f"/api/scans/{sid}/findings?severity=Critical")
    assert sev["count"] >= 1 and all(f["severity_band"] == "Critical" for f in sev["findings"])
    _, srch, _ = call(srv, "GET", f"/api/scans/{sid}/findings?q=ping_host")
    assert srch["count"] >= 1

    fid = lst["findings"][0]["id"]
    code, d, _ = call(srv, "GET", f"/api/findings/{fid}")
    assert code == 200 and d["code"] and d["remediation"] is not None and d["llm_explanation"]
    code, d2, _ = call(srv, "PATCH", f"/api/findings/{fid}", {"triage": "false_positive", "note": "demo"})
    assert code == 200 and d2["triage"] == "false_positive"
    assert call(srv, "PATCH", f"/api/findings/{fid}", {"triage": "nonsense"})[0] == 400
    assert call(srv, "PATCH", "/api/findings/99999", {"triage": "accepted"})[0] == 404

    code, csv_body, hdr = call(srv, "GET", f"/api/scans/{sid}/export?format=csv", raw=True)
    assert code == 200 and csv_body.decode().splitlines()[0].startswith("id,status,severity") and "attachment" in hdr["Content-Disposition"]
    code, sarif, _ = call(srv, "GET", f"/api/scans/{sid}/export?format=sarif")
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"] and sarif["runs"][0]["tool"]["driver"]["rules"]
    res0 = sarif["runs"][0]["results"][0]
    assert res0["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1 and res0["level"] in ("error", "warning", "note")
    code, js, _ = call(srv, "GET", f"/api/scans/{sid}/export?format=json&include=rejected")
    assert all(f["status"] == "rejected" for f in js["findings"])
    assert call(srv, "GET", f"/api/scans/{sid}/export?format=xml")[0] == 400

    code, lst_all, _ = call(srv, "GET", "/api/scans")
    assert lst_all["scans"][0]["id"] == sid and lst_all["active"] is None
    assert call(srv, "DELETE", f"/api/scans/{sid}")[0] == 200
    assert call(srv, "GET", f"/api/scans/{sid}")[0] == 404


def test_start_validation(srv):
    assert call(srv, "POST", "/api/scans", {})[0] == 400
    assert call(srv, "POST", "/api/scans", {"source": "/definitely/not/here"})[0] == 400
    assert call(srv, "POST", "/api/scans", {"source": "demo", "max_llm_chunks": "abc"})[0] == 400
    assert call(srv, "POST", "/api/scans", {"source": "demo", "llm_mode": "yolo"})[0] == 400


def test_second_scan_rejected_while_running_and_cancel(srv, mock_llm, monkeypatch):
    # slow the LLM down so the first scan is still running
    orig = mock_llm._reply
    mock_llm.reply_override = lambda u: (time.sleep(0.15), orig(u))[1]
    code, r, _ = call(srv, "POST", "/api/scans", {"source": "demo"})
    sid = r["scan_id"]
    assert call(srv, "POST", "/api/scans", {"source": "demo"})[0] == 409
    assert call(srv, "DELETE", f"/api/scans/{sid}")[0] == 409
    assert call(srv, "POST", f"/api/scans/{sid}/cancel", {})[0] == 200
    assert wait_done(srv, sid)["status"] == "cancelled"
    assert call(srv, "POST", f"/api/scans/{sid}/cancel", {})[0] == 409   # no longer running
    # a new scan can start after the cancelled one ended
    time.sleep(0.2)
    mock_llm.reply_override = None
    assert call(srv, "POST", "/api/scans", {"source": "demo", "max_llm_chunks": 2})[0] == 202


def test_scan_without_llm_key_gives_unverified(srv, monkeypatch):
    monkeypatch.delenv("LLM_PROVIDER"); monkeypatch.delenv("LLM_BASE_URL")
    _, h, _ = call(srv, "GET", "/api/health")
    assert h["llm"]["configured"] is False
    code, r, _ = call(srv, "POST", "/api/scans", {"source": "demo"})
    scan = wait_done(srv, r["scan_id"])
    assert scan["mode"] == "retrieval-only" and scan["by_status"] == {"unverified": 25}
    assert "No LLM configured" in scan["error"]


def test_llm_test_endpoint(srv, mock_llm):
    code, r, _ = call(srv, "POST", "/api/llm/test", {})
    assert code == 200 and r["ok"] and r["model"] == "mock-model"
    mock_llm.faults = [401]
    code, r, _ = call(srv, "POST", "/api/llm/test", {})
    assert code == 502 and "API key" in r["error"]


def test_save_key_validates_and_writes_env_without_echo(srv, tmp_path):
    assert call(srv, "POST", "/api/llm/key", {"provider": "openai", "key": "x" * 20})[0] == 400
    assert call(srv, "POST", "/api/llm/key", {"provider": "groq", "key": "short"})[0] == 400
    assert call(srv, "POST", "/api/llm/key", {"provider": "groq", "key": "gsk_" + "a" * 30 + " b"})[0] == 400
    key = "gsk_" + "a" * 40
    code, r, _ = call(srv, "POST", "/api/llm/key", {"provider": "groq", "key": key})
    assert code == 200 and key not in json.dumps(r)
    text = (tmp_path / ".env").read_text()
    assert f"GROQ_API_KEY={key}" in text and "LLM_PROVIDER=groq" in text
    call(srv, "POST", "/api/llm/key", {"provider": "groq", "key": "gsk_" + "b" * 40})
    assert (tmp_path / ".env").read_text().count("GROQ_API_KEY=") == 1       # replaced, not duplicated
    os.environ.pop("GROQ_API_KEY", None); os.environ.pop("LLM_PROVIDER", None)


def test_knowledge_base_endpoint(srv):
    _, kb, _ = call(srv, "GET", "/api/knowledge-base")
    assert len(kb["entries"]) == 269 and any(e["cwe_id"] == "CWE-89" for e in kb["entries"])


def test_static_serving_spa_fallback_and_traversal(srv, tmp_path, monkeypatch):
    dist = tmp_path / "dist"; (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<html>INDEX</html>")
    (dist / "assets" / "app.js").write_text("console.log(1)")
    monkeypatch.setattr(api, "DASHBOARD_DIST", str(dist))
    assert b"INDEX" in call(srv, "GET", "/", raw=True)[1]
    code, js, hdr = call(srv, "GET", "/assets/app.js", raw=True)
    assert code == 200 and hdr["Content-Type"].startswith("text/javascript")
    assert b"INDEX" in call(srv, "GET", "/some/client/route", raw=True)[1]          # SPA fallback
    code, body, _ = call(srv, "GET", "/..%2f..%2f..%2fetc/passwd", raw=True)
    assert b"root:" not in body
    assert call(srv, "POST", "/index.html", {})[0] == 405


def test_unknown_endpoint(srv):
    assert call(srv, "GET", "/api/nope")[0] == 404


def test_evaluation_endpoint(srv, tmp_path, monkeypatch):
    monkeypatch.setattr(api, "RESULTS_DIR", str(tmp_path / "res"))
    body = call(srv, "GET", "/api/evaluation")[1]
    assert body["retrieval"] is None and body["llm"] is None and body["kb_entries"] == 269
    (tmp_path / "res").mkdir()
    (tmp_path / "res" / "retrieval_report.json").write_text('{"alpha": 0.5}')
    assert call(srv, "GET", "/api/evaluation")[1]["retrieval"] == {"alpha": 0.5}


def test_inspect_endpoint_exposes_all_retrieval_components(srv):
    code = 'cur.execute("SELECT * FROM users WHERE name = \'" + name + "\'")'
    st, d, _ = call(srv, "POST", "/api/inspect", {"code": code, "language": "python"})
    assert st == 200
    top = d["candidates"][0]
    assert top["id"] == "CWE-89" and top["pattern"] > 0.8 and top["rule_ids"]
    for k in ("dense", "dense_norm", "bm25", "bm25_norm", "prior", "fused", "rank_dense", "rank_bm25", "matched_tokens"):
        assert k in top
    assert d["tokens"] and d["lexical_tokens"] and d["rule_hits"] and "CODE CHUNK" in d["prompt"]["user"]
    # alpha/beta overrides change the fused score the server reports
    _, d0, _ = call(srv, "POST", "/api/inspect", {"code": code, "language": "python", "beta": 0})
    assert d0["candidates"][0]["fused"] < top["fused"]


def test_inspect_validation_and_finding_inspect(srv):
    assert call(srv, "POST", "/api/inspect", {"code": "  "})[0] == 400
    assert call(srv, "POST", "/api/inspect", {"code": "x=1", "alpha": "abc"})[0] == 400
    assert call(srv, "GET", "/api/findings/99999/inspect")[0] == 404


def test_scan_view_has_live_fields_and_pending_rows_are_visible_while_running(srv, mock_llm):
    mock_llm.latency = 0.25                      # keep the LLM pass slow enough to observe the triage state
    code, r, _ = call(srv, "POST", "/api/scans", {"source": "demo", "max_llm_chunks": 40})
    sid = r["scan_id"]
    saw_pending = False
    deadline = time.time() + 60
    while time.time() < deadline:
        _, s, _ = call(srv, "GET", f"/api/scans/{sid}")
        if s["by_status"].get("pending"):
            saw_pending = True
            _, lst, _ = call(srv, "GET", f"/api/scans/{sid}/findings?status=pending")
            assert all(f["status"] == "pending" and f["llm_vulnerable"] is None for f in lst["findings"])
            # severity of verified findings must not include pending (estimated) ones
            assert sum(s["by_severity"].values()) <= sum(s["by_severity_estimated"].values())
        if s["status"] != "running":
            break
        time.sleep(0.05)
    assert saw_pending
    s = wait_done(srv, sid)
    assert "pending" not in s["by_status"]
    assert s["by_file"] and s["by_owasp"] and s["elapsed_s"] is not None and s["counts"]["triage_ready_s"] >= 0
    assert all(isinstance(v, int) for v in s["by_file"].values())


def test_findings_detail_has_remediation_steps_and_language_example(srv, mock_llm):
    mock_llm.reply_override = lambda p: json.dumps({"vulnerable": True, "cwe_id": "CWE-89", "confidence": 0.9, "explanation": "x",
                                                    "evidence": "x", "fix_summary": "fix", "fixed_code": "y"})
    code, r, _ = call(srv, "POST", "/api/scans", {"source": "demo-languages", "max_llm_chunks": 40})
    sid = r["scan_id"]
    wait_done(srv, sid)
    _, lst, _ = call(srv, "GET", f"/api/scans/{sid}/findings?include_rejected=1")
    tagged = []
    for f in lst["findings"]:
        _, d, _ = call(srv, "GET", f"/api/findings/{f['id']}")
        t = d["remediation"] and d["remediation"].get("template")
        if t:
            tagged.append((f["file_path"], t))
    assert tagged
    assert all(t["steps"] and t["reference"] for _, t in tagged)
    java = [t for p, t in tagged if p.endswith(".java")]
    assert java and all(t["language"] == "java" for t in java)
