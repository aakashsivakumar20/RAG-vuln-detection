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
