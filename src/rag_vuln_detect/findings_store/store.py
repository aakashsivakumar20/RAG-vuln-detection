"""
Findings Store module (docs/chapter3_methodology.md §3.4 lists MongoDB as one of
the persistence options; this project uses SQLite -- Python's stdlib `sqlite3`,
zero install -- as a documented substitute).

Why SQLite: the store needs durable, queryable, filterable records that survive
between a scan and later review. SQLite gives that with no server for the user to
install. The schema is document-shaped (one row per finding, JSON columns for the
nested retrieval context and remediation) so moving to MongoDB later is a
one-collection-per-table mapping rather than a redesign.

Two tables
  scans     one row per scan run: repo, mode (llm / retrieval-only), provider/model,
            timings and counters, status (running / done / failed), error text.
  findings  one row per analysed chunk that produced a candidate: location, CWE,
            OWASP category, severity band/score, rationale, retrieval context, the
            LLM verdict (confidence, explanation, evidence, fixed code), the
            remediation (template + LLM), a human triage flag, and a lifecycle status:
                pending       instant retrieval triage row, waiting for the LLM (only exists while a scan runs)
                unverified    retrieval candidate, no LLM available (never claimed as a vulnerability)
                confirmed     LLM judged it vulnerable with high confidence
                needs_review  LLM judged it vulnerable with low confidence
                rejected      LLM judged it NOT vulnerable (kept for transparency/precision numbers)
                candidate     legacy value from the earlier retrieval-only prototype

Databases created by the earlier prototype are migrated in place (missing columns
are added with ALTER TABLE), so old data/findings.db files keep working.
"""

from __future__ import annotations

import dataclasses
import datetime
import json
import os
import sqlite3
from contextlib import closing

_HERE = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_DB_PATH = os.path.join(_HERE, "..", "..", "..", "data", "findings.db")

STATUSES = ("pending", "unverified", "confirmed", "needs_review", "rejected", "candidate")
TRIAGE_VALUES = ("", "accepted", "false_positive")

_BASE_SCHEMA = """
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
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_url      TEXT NOT NULL,
    mode          TEXT,
    provider      TEXT,
    model         TEXT,
    status        TEXT NOT NULL DEFAULT 'running',
    stage         TEXT,
    progress      REAL NOT NULL DEFAULT 0,
    params        TEXT,
    counts        TEXT,
    timings       TEXT,
    error         TEXT,
    started_at    TEXT NOT NULL,
    finished_at   TEXT
);
"""

# Columns added after the first prototype: (name, SQL type/default). Applied by _migrate().
_ADDED_FINDING_COLUMNS = [
    ("scan_id", "INTEGER"),
    ("code", "TEXT"),
    ("retrieval_cwe", "TEXT"),
    ("retrieval_agrees", "INTEGER"),
    ("llm_vulnerable", "INTEGER"),
    ("llm_confidence", "REAL"),
    ("llm_explanation", "TEXT"),
    ("llm_evidence", "TEXT"),
    ("llm_model", "TEXT"),
    ("remediation", "TEXT"),
    ("triage", "TEXT NOT NULL DEFAULT ''"),
    ("triage_note", "TEXT"),
]

_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_findings_repo ON findings(repo_url);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity_band);
CREATE INDEX IF NOT EXISTS idx_findings_cwe ON findings(cwe_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
"""

# Keep the old module-level name some callers/tests may import.
_SCHEMA = _BASE_SCHEMA


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
    # --- fields added with the LLM verdict step (all optional) ---
    scan_id: int | None = None
    code: str | None = None
    retrieval_cwe: str | None = None
    retrieval_agrees: bool | None = None
    llm_vulnerable: bool | None = None
    llm_confidence: float | None = None
    llm_explanation: str | None = None
    llm_evidence: str | None = None
    llm_model: str | None = None
    remediation: dict | None = None
    triage: str = ""
    triage_note: str | None = None

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


_INSERT_COLUMNS = [f.name for f in dataclasses.fields(Finding) if f.name not in ("id", "created_at")] + ["created_at"]
_JSON_COLUMNS = {"retrieved_kb_context", "remediation"}
_BOOL_COLUMNS = {"low_confidence", "retrieval_agrees", "llm_vulnerable"}


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    have = {r["name"] for r in conn.execute("PRAGMA table_info(findings)")}
    for name, decl in _ADDED_FINDING_COLUMNS:
        if name not in have:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {name} {decl}")


def init_db(db_path: str = _DEFAULT_DB_PATH) -> None:
    """Create/upgrade the schema (and parent dir). Safe to call repeatedly."""
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    with closing(_connect(db_path)) as conn:
        conn.executescript(_BASE_SCHEMA)
        _migrate(conn)
        conn.executescript(_INDEXES)
        conn.commit()


# ---------------------------------------------------------------------- findings

def _encode(finding: Finding, created_at: str) -> list:
    d = dataclasses.asdict(finding)
    d["created_at"] = created_at
    out = []
    for col in _INSERT_COLUMNS:
        v = d[col]
        if col in _JSON_COLUMNS:
            v = json.dumps(v) if v is not None else None
        elif col in _BOOL_COLUMNS and v is not None:
            v = int(bool(v))
        out.append(v)
    return out


def insert_finding(finding: Finding, db_path: str = _DEFAULT_DB_PATH) -> int:
    """Insert one finding, returning its new row id."""
    init_db(db_path)
    cols = ", ".join(_INSERT_COLUMNS)
    marks = ", ".join("?" for _ in _INSERT_COLUMNS)
    with closing(_connect(db_path)) as conn:
        cur = conn.execute(f"INSERT INTO findings ({cols}) VALUES ({marks})",
                           _encode(finding, finding.created_at or _now()))
        conn.commit()
        return cur.lastrowid


def replace_finding(finding_id: int, finding: Finding, db_path: str = _DEFAULT_DB_PATH) -> bool:
    """Overwrite every analysis field of an existing row (used when the LLM verdict replaces a triage row)."""
    init_db(db_path)
    cols = [c for c in _INSERT_COLUMNS if c not in ("created_at", "triage", "triage_note")]
    enc = dict(zip(_INSERT_COLUMNS, _encode(finding, finding.created_at or _now())))
    sets = ", ".join(f"{c} = ?" for c in cols)
    with closing(_connect(db_path)) as conn:
        cur = conn.execute(f"UPDATE findings SET {sets} WHERE id = ?", [*(enc[c] for c in cols), finding_id])
        conn.commit()
        return cur.rowcount > 0


def finalize_pending(scan_id: int, reason: str, db_path: str = _DEFAULT_DB_PATH) -> int:
    """Turn leftover 'pending' triage rows of a scan into honest 'unverified' candidates."""
    init_db(db_path)
    with closing(_connect(db_path)) as conn:
        cur = conn.execute(
            "UPDATE findings SET status = 'unverified', rationale = COALESCE(rationale, '') || ? "
            "WHERE scan_id = ? AND status = 'pending'", (f" ({reason})", scan_id))
        conn.commit()
        return cur.rowcount


def _row_to_finding(row: sqlite3.Row) -> Finding:
    keys = row.keys()
    kw = {}
    for f in dataclasses.fields(Finding):
        if f.name not in keys:
            continue
        v = row[f.name]
        if f.name in _JSON_COLUMNS:
            v = json.loads(v) if v else ([] if f.name == "retrieved_kb_context" else None)
        elif f.name in _BOOL_COLUMNS and v is not None:
            v = bool(v)
        kw[f.name] = v
    if kw.get("triage") is None:
        kw["triage"] = ""
    return Finding(**kw)


def get_finding(finding_id: int, db_path: str = _DEFAULT_DB_PATH) -> Finding | None:
    init_db(db_path)
    with closing(_connect(db_path)) as conn:
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
    return _row_to_finding(row) if row else None


_SEVERITY_ORDER = "CASE severity_band WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END"


def query_findings(
    repo_url: str | None = None,
    severity_band: str | None = None,
    cwe_id: str | None = None,
    db_path: str = _DEFAULT_DB_PATH,
    *,
    scan_id: int | None = None,
    status: str | list | tuple | None = None,
    order: str = "newest",
) -> list[Finding]:
    """Query findings with optional equality filters. order: 'newest' (default) or 'severity'."""
    init_db(db_path)
    clauses, params = [], []
    for col, val in (("repo_url", repo_url), ("severity_band", severity_band), ("cwe_id", cwe_id), ("scan_id", scan_id)):
        if val is not None:
            clauses.append(f"{col} = ?")
            params.append(val)
    if status is not None:
        statuses = [status] if isinstance(status, str) else list(status)
        clauses.append(f"status IN ({','.join('?' for _ in statuses)})")
        params.extend(statuses)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    order_sql = f"{_SEVERITY_ORDER}, severity_score DESC, id DESC" if order == "severity" else "id DESC"
    with closing(_connect(db_path)) as conn:
        rows = conn.execute(f"SELECT * FROM findings {where} ORDER BY {order_sql}", params).fetchall()
    return [_row_to_finding(r) for r in rows]


def count_by_severity(repo_url: str | None = None, db_path: str = _DEFAULT_DB_PATH, *,
                      scan_id: int | None = None, exclude_rejected: bool = False,
                      exclude_pending: bool = False) -> dict[str, int]:
    """{severity_band: count}. Rejected findings carry band 'None' and can be excluded."""
    init_db(db_path)
    clauses, params = [], []
    if repo_url:
        clauses.append("repo_url = ?"); params.append(repo_url)
    if scan_id is not None:
        clauses.append("scan_id = ?"); params.append(scan_id)
    if exclude_rejected:
        clauses.append("status != 'rejected'")
    if exclude_pending:
        clauses.append("status != 'pending'")
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with closing(_connect(db_path)) as conn:
        rows = conn.execute(f"SELECT severity_band, COUNT(*) FROM findings {where} GROUP BY severity_band", params).fetchall()
    return {r[0]: r[1] for r in rows}


def count_by_status(scan_id: int | None = None, repo_url: str | None = None,
                    db_path: str = _DEFAULT_DB_PATH) -> dict[str, int]:
    init_db(db_path)
    clauses, params = [], []
    if repo_url:
        clauses.append("repo_url = ?"); params.append(repo_url)
    if scan_id is not None:
        clauses.append("scan_id = ?"); params.append(scan_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with closing(_connect(db_path)) as conn:
        rows = conn.execute(f"SELECT status, COUNT(*) FROM findings {where} GROUP BY status", params).fetchall()
    return {r[0]: r[1] for r in rows}


def count_by_cwe(scan_id: int, db_path: str = _DEFAULT_DB_PATH, include_rejected: bool = False) -> dict[str, int]:
    init_db(db_path)
    extra = "" if include_rejected else "AND status != 'rejected'"
    with closing(_connect(db_path)) as conn:
        rows = conn.execute(f"SELECT COALESCE(cwe_id, owasp_category, 'unknown'), COUNT(*) FROM findings "
                            f"WHERE scan_id = ? {extra} GROUP BY 1 ORDER BY 2 DESC", (scan_id,)).fetchall()
    return {r[0]: r[1] for r in rows}


def count_by_column(scan_id: int, column: str, db_path: str = _DEFAULT_DB_PATH, limit: int = 8) -> dict[str, int]:
    """Top values of file_path / owasp_category for a scan (rejected findings excluded)."""
    if column not in ("file_path", "owasp_category"):
        raise ValueError("column must be file_path or owasp_category")
    init_db(db_path)
    with closing(_connect(db_path)) as conn:
        rows = conn.execute(f"SELECT COALESCE({column}, 'unknown'), COUNT(*) FROM findings "
                            f"WHERE scan_id = ? AND status != 'rejected' GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT ?",
                            (scan_id, limit)).fetchall()
    return {r[0]: r[1] for r in rows}


def set_triage(finding_id: int, triage: str, note: str | None = None, db_path: str = _DEFAULT_DB_PATH) -> bool:
    """Record the human reviewer's decision ('accepted' / 'false_positive' / '' to clear)."""
    if triage not in TRIAGE_VALUES:
        raise ValueError(f"triage must be one of {TRIAGE_VALUES}")
    init_db(db_path)
    with closing(_connect(db_path)) as conn:
        cur = conn.execute("UPDATE findings SET triage = ?, triage_note = ? WHERE id = ?", (triage, note, finding_id))
        conn.commit()
        return cur.rowcount > 0


def delete_findings_for_repo(repo_url: str, db_path: str = _DEFAULT_DB_PATH) -> int:
    """Delete all findings for one repo (used by the legacy prototype to avoid duplicates)."""
    init_db(db_path)
    with closing(_connect(db_path)) as conn:
        cur = conn.execute("DELETE FROM findings WHERE repo_url = ?", (repo_url,))
        conn.commit()
        return cur.rowcount


# ------------------------------------------------------------------------- scans

_SCAN_JSON = ("params", "counts", "timings")


def create_scan(repo_url: str, mode: str = "", provider: str = "", model: str = "",
                params: dict | None = None, db_path: str = _DEFAULT_DB_PATH) -> int:
    init_db(db_path)
    with closing(_connect(db_path)) as conn:
        cur = conn.execute(
            "INSERT INTO scans (repo_url, mode, provider, model, status, stage, params, started_at) "
            "VALUES (?, ?, ?, ?, 'running', 'queued', ?, ?)",
            (repo_url, mode, provider, model, json.dumps(params or {}), _now()))
        conn.commit()
        return cur.lastrowid


def update_scan(scan_id: int, db_path: str = _DEFAULT_DB_PATH, **fields) -> None:
    """Update scan columns (status, stage, progress, mode, provider, model, error, counts, timings, params)."""
    allowed = {"status", "stage", "progress", "mode", "provider", "model", "error", "counts", "timings", "params", "finished_at"}
    bad = set(fields) - allowed
    if bad:
        raise ValueError(f"unknown scan fields: {sorted(bad)}")
    if not fields:
        return
    vals = [json.dumps(v) if k in _SCAN_JSON else v for k, v in fields.items()]
    sets = ", ".join(f"{k} = ?" for k in fields)
    init_db(db_path)
    with closing(_connect(db_path)) as conn:
        conn.execute(f"UPDATE scans SET {sets} WHERE id = ?", [*vals, scan_id])
        conn.commit()


def finish_scan(scan_id: int, status: str = "done", error: str | None = None, db_path: str = _DEFAULT_DB_PATH, **fields) -> None:
    update_scan(scan_id, db_path=db_path, status=status, error=error, finished_at=_now(),
                **({"progress": 1.0} if status == "done" else {}), **fields)


def _scan_row(row: sqlite3.Row) -> dict:
    d = dict(row)
    for k in _SCAN_JSON:
        d[k] = json.loads(d[k]) if d.get(k) else {}
    return d


def get_scan(scan_id: int, db_path: str = _DEFAULT_DB_PATH) -> dict | None:
    init_db(db_path)
    with closing(_connect(db_path)) as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return _scan_row(row) if row else None


def list_scans(limit: int = 50, db_path: str = _DEFAULT_DB_PATH) -> list[dict]:
    init_db(db_path)
    with closing(_connect(db_path)) as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [_scan_row(r) for r in rows]


def delete_scan(scan_id: int, db_path: str = _DEFAULT_DB_PATH) -> bool:
    init_db(db_path)
    with closing(_connect(db_path)) as conn:
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        return cur.rowcount > 0


def mark_interrupted_scans(db_path: str = _DEFAULT_DB_PATH) -> int:
    """Scans still 'running' when the server (re)starts were killed mid-way; mark them failed."""
    init_db(db_path)
    with closing(_connect(db_path)) as conn:
        cur = conn.execute("UPDATE scans SET status='failed', error='interrupted (server restarted)', finished_at=? "
                           "WHERE status='running'", (_now(),))
        conn.commit()
        return cur.rowcount
