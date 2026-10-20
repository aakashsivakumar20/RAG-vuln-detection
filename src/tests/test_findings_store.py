"""
Automated tests for the Findings Store module (findings_store/store.py, the
SQLite-based substitute for MongoDB -- see module docstring). Run with:
    cd src && python -m pytest tests/ -v
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rag_vuln_detect.findings_store.store import (
    Finding,
    init_db,
    insert_finding,
    query_findings,
    count_by_severity,
    delete_findings_for_repo,
)


def _sample_finding(**overrides) -> Finding:
    base = dict(
        repo_url="https://github.com/OWASP/NodeGoat.git",
        chunk_id="app/routes/session.js::login::10-30",
        file_path="app/routes/session.js",
        start_line=10,
        end_line=30,
        chunk_name="login",
        chunk_kind="function",
        cwe_id="CWE-89",
        owasp_category="A05:2025",
        severity_band="Critical",
        severity_score=9.8,
        margin=0.042,
        low_confidence=False,
        rationale="Base severity for CWE-89 is Critical (9.8) ...",
        retrieved_kb_context=[{"id": "CWE-89", "similarity": 0.93}],
    )
    base.update(overrides)
    return Finding(**base)


def test_init_db_creates_file(tmp_path):
    db_path = str(tmp_path / "findings.db")
    assert not os.path.exists(db_path)
    init_db(db_path)
    assert os.path.exists(db_path)


def test_insert_and_query_round_trip(tmp_path):
    db_path = str(tmp_path / "findings.db")
    fid = insert_finding(_sample_finding(), db_path=db_path)
    assert fid == 1

    rows = query_findings(db_path=db_path)
    assert len(rows) == 1
    row = rows[0]
    assert row.id == 1
    assert row.cwe_id == "CWE-89"
    assert row.severity_band == "Critical"
    assert row.low_confidence is False
    assert row.retrieved_kb_context == [{"id": "CWE-89", "similarity": 0.93}]
    assert row.created_at is not None


def test_query_filters_by_repo_url(tmp_path):
    db_path = str(tmp_path / "findings.db")
    insert_finding(_sample_finding(repo_url="https://github.com/a/a.git"), db_path=db_path)
    insert_finding(_sample_finding(repo_url="https://github.com/b/b.git"), db_path=db_path)

    a_rows = query_findings(repo_url="https://github.com/a/a.git", db_path=db_path)
    assert len(a_rows) == 1
    assert a_rows[0].repo_url == "https://github.com/a/a.git"


def test_query_filters_by_severity_band(tmp_path):
    db_path = str(tmp_path / "findings.db")
    insert_finding(_sample_finding(severity_band="Critical"), db_path=db_path)
    insert_finding(_sample_finding(severity_band="Low", cwe_id="CWE-770"), db_path=db_path)

    critical = query_findings(severity_band="Critical", db_path=db_path)
    assert len(critical) == 1
    assert critical[0].severity_band == "Critical"


def test_count_by_severity_aggregates_correctly(tmp_path):
    db_path = str(tmp_path / "findings.db")
    insert_finding(_sample_finding(severity_band="Critical"), db_path=db_path)
    insert_finding(_sample_finding(severity_band="Critical", chunk_id="c2"), db_path=db_path)
    insert_finding(_sample_finding(severity_band="Medium", chunk_id="c3", cwe_id="CWE-79"), db_path=db_path)

    counts = count_by_severity(db_path=db_path)
    assert counts["Critical"] == 2
    assert counts["Medium"] == 1


def test_delete_findings_for_repo_removes_only_that_repo(tmp_path):
    db_path = str(tmp_path / "findings.db")
    insert_finding(_sample_finding(repo_url="https://github.com/a/a.git"), db_path=db_path)
    insert_finding(_sample_finding(repo_url="https://github.com/b/b.git"), db_path=db_path)

    deleted = delete_findings_for_repo("https://github.com/a/a.git", db_path=db_path)
    assert deleted == 1
    remaining = query_findings(db_path=db_path)
    assert len(remaining) == 1
    assert remaining[0].repo_url == "https://github.com/b/b.git"


def test_results_ordered_newest_first(tmp_path):
    db_path = str(tmp_path / "findings.db")
    insert_finding(_sample_finding(chunk_id="first"), db_path=db_path)
    insert_finding(_sample_finding(chunk_id="second"), db_path=db_path)

    rows = query_findings(db_path=db_path)
    assert rows[0].chunk_id == "second"
    assert rows[1].chunk_id == "first"


# ------------------------------------------------- v2: migration, scans, triage

import sqlite3

from rag_vuln_detect.findings_store.store import (
    count_by_status, count_by_cwe, create_scan, delete_scan, finish_scan, get_finding, get_scan,
    list_scans, mark_interrupted_scans, set_triage, update_scan,
)

_OLD_SCHEMA = """CREATE TABLE findings (id INTEGER PRIMARY KEY AUTOINCREMENT, repo_url TEXT NOT NULL, chunk_id TEXT NOT NULL,
file_path TEXT NOT NULL, start_line INTEGER, end_line INTEGER, chunk_name TEXT, chunk_kind TEXT, cwe_id TEXT,
owasp_category TEXT, severity_band TEXT NOT NULL, severity_score REAL NOT NULL, margin REAL NOT NULL,
low_confidence INTEGER NOT NULL, rationale TEXT, retrieved_kb_context TEXT, status TEXT NOT NULL DEFAULT 'candidate',
created_at TEXT NOT NULL);"""


def test_old_database_is_migrated_in_place(tmp_path):
    db = str(tmp_path / "old.db")
    with sqlite3.connect(db) as c:
        c.execute(_OLD_SCHEMA)
        c.execute("INSERT INTO findings (repo_url,chunk_id,file_path,severity_band,severity_score,margin,low_confidence,"
                  "retrieved_kb_context,created_at) VALUES ('r','c','f.py','High',7.5,0.1,0,'[{\"id\":\"CWE-22\"}]','2026-01-01')")
    rows = query_findings(db_path=db)
    assert len(rows) == 1 and rows[0].status == "candidate" and rows[0].triage == "" and rows[0].remediation is None
    fid = insert_finding(_sample_finding(llm_confidence=0.9, remediation={"title": "t"}), db_path=db)
    assert get_finding(fid, db_path=db).remediation == {"title": "t"}


def test_v2_fields_round_trip(tmp_path):
    db = str(tmp_path / "f.db")
    f = _sample_finding(status="confirmed", scan_id=3, code="x = 1", retrieval_cwe="CWE-89", retrieval_agrees=True,
                        llm_vulnerable=True, llm_confidence=0.93, llm_explanation="because", llm_evidence="ev",
                        llm_model="m", remediation={"title": "t", "before": "a", "after": "b"})
    fid = insert_finding(f, db_path=db)
    g = get_finding(fid, db_path=db)
    assert g.retrieval_agrees is True and g.llm_vulnerable is True and g.llm_confidence == 0.93
    assert g.remediation["after"] == "b" and g.scan_id == 3 and g.low_confidence is False
    assert get_finding(999, db_path=db) is None


def test_status_filters_counts_and_severity_order(tmp_path):
    db = str(tmp_path / "f.db")
    insert_finding(_sample_finding(severity_band="Low", severity_score=3.0, status="confirmed", scan_id=1, cwe_id="CWE-79"), db_path=db)
    insert_finding(_sample_finding(severity_band="Critical", status="confirmed", scan_id=1), db_path=db)
    insert_finding(_sample_finding(severity_band="None", severity_score=0.0, status="rejected", scan_id=1), db_path=db)
    insert_finding(_sample_finding(status="unverified", scan_id=2), db_path=db)
    assert [r.severity_band for r in query_findings(scan_id=1, status=["confirmed", "rejected"], order="severity", db_path=db)] == ["Critical", "Low", "None"]
    assert count_by_status(scan_id=1, db_path=db) == {"confirmed": 2, "rejected": 1}
    assert count_by_severity(scan_id=1, exclude_rejected=True, db_path=db) == {"Low": 1, "Critical": 1}
    assert count_by_cwe(1, db_path=db) == {"CWE-89": 1, "CWE-79": 1}


def test_triage(tmp_path):
    db = str(tmp_path / "f.db")
    fid = insert_finding(_sample_finding(), db_path=db)
    assert set_triage(fid, "false_positive", "test fixture", db_path=db)
    g = get_finding(fid, db_path=db)
    assert (g.triage, g.triage_note) == ("false_positive", "test fixture")
    assert set_triage(fid, "", db_path=db) and get_finding(fid, db_path=db).triage == ""
    assert not set_triage(12345, "accepted", db_path=db)
    import pytest
    with pytest.raises(ValueError):
        set_triage(fid, "bogus", db_path=db)


def test_scan_lifecycle(tmp_path):
    db = str(tmp_path / "f.db")
    sid = create_scan("https://x/y.git", mode="llm", params={"max_llm": 5}, db_path=db)
    s = get_scan(sid, db_path=db)
    assert s["status"] == "running" and s["params"] == {"max_llm": 5} and s["counts"] == {}
    update_scan(sid, db_path=db, stage="embedding", progress=0.4, counts={"chunks": 10})
    assert get_scan(sid, db_path=db)["counts"] == {"chunks": 10}
    finish_scan(sid, db_path=db, timings={"total": 1.2})
    s = get_scan(sid, db_path=db)
    assert s["status"] == "done" and s["progress"] == 1.0 and s["finished_at"] and s["timings"] == {"total": 1.2}
    import pytest
    with pytest.raises(ValueError):
        update_scan(sid, db_path=db, nonsense=1)
    assert [x["id"] for x in list_scans(db_path=db)] == [sid]


def test_interrupted_and_delete_scan(tmp_path):
    db = str(tmp_path / "f.db")
    a = create_scan("r", db_path=db); b = create_scan("r", db_path=db)
    finish_scan(b, db_path=db)
    insert_finding(_sample_finding(scan_id=a), db_path=db)
    assert mark_interrupted_scans(db_path=db) == 1
    assert get_scan(a, db_path=db)["status"] == "failed" and get_scan(b, db_path=db)["status"] == "done"
    assert delete_scan(a, db_path=db) and get_scan(a, db_path=db) is None and query_findings(db_path=db) == []
    assert not delete_scan(a, db_path=db)
