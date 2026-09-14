"""
Findings Store module (per docs/chapter3_methodology.md §3.4 tech-stack list,
which named MongoDB as one of the persistence options to be decided during
implementation).

Environment note -- documented substitution:
This sandbox environment has no installable MongoDB server package
(confirmed via `apt-cache search mongodb`, which returns only client-library
bindings, no `mongodb` / `mongodb-org` server package in the available apt
sources). Rather than skip the module or fake a connection, this
implementation uses **SQLite** (Python's stdlib `sqlite3`, no extra
dependency) as a documented, honest substitute that satisfies the same
functional requirement this module exists to fulfil: durably persisting
"candidate findings" produced by a scan so they can be queried, filtered,
and reviewed later without re-running the pipeline. The schema below is
intentionally document-shaped (one row per finding, with a JSON column for
the nested retrieved-KB-context list) so a later migration to MongoDB, if
still desired for Project II, is a straightforward one-collection-per-table
mapping rather than a redesign.

IMPORTANT -- candidate findings, not verified vulnerabilities:
Every row this module stores is a *candidate* finding: a code chunk paired
with its nearest Security Knowledge Base match and a rule-based severity
assessment (severity/scorer.py). None of this has been confirmed by the LLM
Security Analysis stage (Review 4/5 scope, not yet implemented) -- see
pipeline/full_scan.py, which is the only writer of this store, and
docs/chapter4_implementation.md for the full framing.
"""

from __future__ import annotations

import dataclasses
import datetime
import json
import os
import sqlite3

_HERE = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_DB_PATH = os.path.join(_HERE, "..", "..", "..", "data", "findings.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_url            TEXT NOT NULL,
    chunk_id            TEXT NOT NULL,
    file_path           TEXT NOT NULL,
    start_line          INTEGER,
    end_line            INTEGER,
    chunk_name          TEXT,
    chunk_kind          TEXT,
    cwe_id              TEXT,
    owasp_category      TEXT,
    severity_band       TEXT NOT NULL,
    severity_score      REAL NOT NULL,
    margin              REAL NOT NULL,
    low_confidence      INTEGER NOT NULL,
    rationale           TEXT,
    retrieved_kb_context TEXT,
    status              TEXT NOT NULL DEFAULT 'candidate',
    created_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_repo ON findings(repo_url);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity_band);
CREATE INDEX IF NOT EXISTS idx_findings_cwe ON findings(cwe_id);
"""


@dataclasses.dataclass
class Finding:
    repo_url: str
    chunk_id: str
    file_path: str
    start_line: int | None
    end_line: int | None
    chunk_name: str | None
    chunk_kind: str | None
    cwe_id: str | None
    owasp_category: str | None
    severity_band: str
    severity_score: float
    margin: float
    low_confidence: bool
    rationale: str
    retrieved_kb_context: list
    status: str = "candidate"
    id: int | None = None
    created_at: str | None = None


def init_db(db_path: str = _DEFAULT_DB_PATH) -> None:
    """Create the findings table (and parent dir) if it does not exist yet."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.executescript(_SCHEMA)


def insert_finding(finding: Finding, db_path: str = _DEFAULT_DB_PATH) -> int:
    """Insert one candidate finding, returning its new row id."""
    init_db(db_path)
    created_at = finding.created_at or datetime.datetime.utcnow().isoformat()
    with sqlite3.connect(db_path) as conn:
        cur = conn.execute(
            """
            INSERT INTO findings (
                repo_url, chunk_id, file_path, start_line, end_line,
                chunk_name, chunk_kind, cwe_id, owasp_category,
                severity_band, severity_score, margin, low_confidence,
                rationale, retrieved_kb_context, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.repo_url, finding.chunk_id, finding.file_path,
                finding.start_line, finding.end_line, finding.chunk_name,
                finding.chunk_kind, finding.cwe_id, finding.owasp_category,
                finding.severity_band, finding.severity_score, finding.margin,
                int(finding.low_confidence), finding.rationale,
                json.dumps(finding.retrieved_kb_context), finding.status,
                created_at,
            ),
        )
        return cur.lastrowid


def _row_to_finding(row: sqlite3.Row) -> Finding:
    return Finding(
        id=row["id"],
        repo_url=row["repo_url"],
        chunk_id=row["chunk_id"],
        file_path=row["file_path"],
        start_line=row["start_line"],
        end_line=row["end_line"],
        chunk_name=row["chunk_name"],
        chunk_kind=row["chunk_kind"],
        cwe_id=row["cwe_id"],
        owasp_category=row["owasp_category"],
        severity_band=row["severity_band"],
        severity_score=row["severity_score"],
        margin=row["margin"],
        low_confidence=bool(row["low_confidence"]),
        rationale=row["rationale"],
        retrieved_kb_context=json.loads(row["retrieved_kb_context"] or "[]"),
        status=row["status"],
        created_at=row["created_at"],
    )


def query_findings(
    repo_url: str | None = None,
    severity_band: str | None = None,
    cwe_id: str | None = None,
    db_path: str = _DEFAULT_DB_PATH,
) -> list[Finding]:
    """Query findings with optional equality filters, newest first."""
    init_db(db_path)
    clauses, params = [], []
    if repo_url is not None:
        clauses.append("repo_url = ?")
        params.append(repo_url)
    if severity_band is not None:
        clauses.append("severity_band = ?")
        params.append(severity_band)
    if cwe_id is not None:
        clauses.append("cwe_id = ?")
        params.append(cwe_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"SELECT * FROM findings {where} ORDER BY id DESC", params
        ).fetchall()
    return [_row_to_finding(r) for r in rows]


def count_by_severity(repo_url: str | None = None, db_path: str = _DEFAULT_DB_PATH) -> dict[str, int]:
    """Return {severity_band: count} for a repo scan (or all scans)."""
    init_db(db_path)
    where = "WHERE repo_url = ?" if repo_url else ""
    params = [repo_url] if repo_url else []
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            f"SELECT severity_band, COUNT(*) FROM findings {where} GROUP BY severity_band",
            params,
        ).fetchall()
    return {band: n for band, n in rows}


def delete_findings_for_repo(repo_url: str, db_path: str = _DEFAULT_DB_PATH) -> int:
    """Delete all findings for one repo (used to avoid duplicate rows on re-scan)."""
    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        cur = conn.execute("DELETE FROM findings WHERE repo_url = ?", (repo_url,))
        return cur.rowcount
