"""
Local HTTP API + dashboard host (standard library only: no Flask/FastAPI to install).

    python -m rag_vuln_detect.api.server [--port 8000] [--host 127.0.0.1] [--no-browser]

Serves the prebuilt React dashboard (dashboard/dist) and a JSON API under /api:

  GET    /api/health                       status of the KB, database and LLM configuration
  POST   /api/llm/test                     one tiny request to verify the configured key
  POST   /api/llm/key                      save a provider key to .env (never echoed back)
  GET    /api/knowledge-base               the OWASP/CWE entries the retriever searches
  GET    /api/evaluation                   saved evaluation results (retrieval benchmark, LLM benchmark if run)
  GET    /api/scans                        recent scans
  POST   /api/scans                        start a scan {source, max_llm_chunks, use_rag, ...} (source "demo" = bundled Python/JS app, "demo-languages" = bundled multi-language app)
  GET    /api/scans/<id>                   scan + live progress + summary tables
  DELETE /api/scans/<id>
  POST   /api/scans/<id>/cancel
  GET    /api/scans/<id>/findings          ?status=&severity=&cwe=&q=&include_rejected=1
  GET    /api/scans/<id>/export            ?format=json|csv|sarif&include=confirmed,needs_review
  GET    /api/findings/<id>                full finding (code, LLM verdict, remediation)
  PATCH  /api/findings/<id>                {triage: accepted|false_positive|"", note}
  POST   /api/inspect                      retrieval x-ray for pasted code {code, language, alpha?, beta?, top_k?}
  GET    /api/findings/<id>/inspect        retrieval x-ray for a finding's code chunk (same numbers the scan used)

Safety: binds to 127.0.0.1 by default; rejects requests whose Host header is not local (DNS-rebinding),
and requires application/json on writes (browsers cannot send that cross-origin without a preflight,
which this server never approves) so a random web page cannot trigger scans.
"""

from __future__ import annotations

import argparse
import datetime
import json
import mimetypes
import os
import re
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from rag_vuln_detect.api import exporters
from rag_vuln_detect.findings_store import store
from rag_vuln_detect.knowledge_base.build_kb import load_kb_records
from rag_vuln_detect.llm import providers
from rag_vuln_detect.llm.analyzer import SecurityAnalyzer, VerdictCache
from rag_vuln_detect.pipeline.scan import ScanConfig, run_scan

PROJECT_ROOT = providers.PROJECT_ROOT
DASHBOARD_DIST = os.path.join(PROJECT_ROOT, "dashboard", "dist")
DEMO_APP = os.path.join(PROJECT_ROOT, "demo", "vulnerable_demo_app")
DEMO_APP_LANGS = os.path.join(PROJECT_ROOT, "demo", "multilang_demo_app")
RESULTS_DIR = os.path.join(PROJECT_ROOT, "results")
VERSION = "3.0.0"
MAX_BODY = 1_000_000
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1"}
_KEY_ENV = {"groq": "GROQ_API_KEY", "gemini": "GEMINI_API_KEY"}


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


# --------------------------------------------------------------------- scan manager

class ScanManager:
    """Runs scans on background threads (one at a time) and keeps their live status message."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._active: int | None = None
        self._cancel: dict[int, threading.Event] = {}
        self.messages: dict[int, str] = {}
        store.mark_interrupted_scans(db_path)

    def start(self, source: str, cfg: ScanConfig) -> int:
        with self._lock:
            if self._active is not None:
                raise ApiError(409, f"scan #{self._active} is still running - wait for it or cancel it first")
            analyzer = SecurityAnalyzer(providers.make_provider(), mode=cfg.llm_mode)
            scan_id = store.create_scan(source, params=cfg.__dict__, db_path=self.db_path)
            self._active = scan_id
            self._cancel[scan_id] = threading.Event()
        threading.Thread(target=self._run, args=(scan_id, source, cfg, analyzer), daemon=True).start()
        return scan_id

    def _run(self, scan_id, source, cfg, analyzer):
        try:
            run_scan(source, cfg, analyzer=analyzer, db_path=self.db_path, scan_id=scan_id,
                     progress=lambda stage, frac, msg: self.messages.__setitem__(scan_id, msg),
                     should_cancel=self._cancel[scan_id].is_set)
        except Exception:  # noqa: BLE001 - already recorded on the scan row by run_scan
            pass
        finally:
            with self._lock:
                self._active = None

    def cancel(self, scan_id: int) -> bool:
        ev = self._cancel.get(scan_id)
        if ev and self._active == scan_id:
            ev.set()
            return True
        return False

    @property
    def active(self):
        return self._active


# -------------------------------------------------------------------------- helpers

def _public_finding(f: store.Finding, full: bool = False) -> dict:
    d = f.to_dict()
    if not full:
        for k in ("code", "remediation", "retrieved_kb_context", "llm_evidence", "rationale"):
            d.pop(k, None)
        d["has_remediation"] = f.remediation is not None
    return d


def _llm_status() -> dict:
    try:
        p = providers.make_provider()
    except providers.LLMError as e:
        return {"configured": False, "error": str(e)}
    if p is None:
        return {"configured": False, "providers": ["groq", "gemini"]}
    return {"configured": True, "provider": p.name, "model": p._model or "(auto-detected on first use)"}


def _scan_view(mgr: ScanManager, scan_id: int) -> dict:
    scan = store.get_scan(scan_id, db_path=mgr.db_path)
    if not scan:
        raise ApiError(404, "scan not found")
    scan["message"] = mgr.messages.get(scan_id, "")
    scan["by_status"] = store.count_by_status(scan_id=scan_id, db_path=mgr.db_path)
    scan["by_severity"] = store.count_by_severity(scan_id=scan_id, exclude_rejected=True, exclude_pending=True,
                                                  db_path=mgr.db_path)
    scan["by_severity_estimated"] = store.count_by_severity(scan_id=scan_id, exclude_rejected=True, db_path=mgr.db_path)
    scan["by_cwe"] = store.count_by_cwe(scan_id, db_path=mgr.db_path)
    scan["by_file"] = store.count_by_column(scan_id, "file_path", db_path=mgr.db_path)
    scan["by_owasp"] = store.count_by_column(scan_id, "owasp_category", db_path=mgr.db_path)
    try:
        started = datetime.datetime.fromisoformat(scan["started_at"])
        end = (datetime.datetime.fromisoformat(scan["finished_at"]) if scan.get("finished_at")
               else datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None))
        scan["elapsed_s"] = max(0.0, round((end - started).total_seconds(), 1))
    except (TypeError, ValueError):
        scan["elapsed_s"] = None
    return scan


def _update_env_file(var: str, value: str) -> None:
    path = os.path.join(PROJECT_ROOT, ".env")
    lines = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    out, done = [], False
    for ln in lines:
        if re.match(rf"\s*{re.escape(var)}\s*=", ln):
            out.append(f"{var}={value}")
            done = True
        else:
            out.append(ln)
    if not done:
        out.append(f"{var}={value}")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")


# --------------------------------------------------------------------------- handler

def make_handler(mgr: ScanManager):
    routes: list[tuple[str, re.Pattern, str]] = []

    def route(method, pattern):
        def deco(fn):
            routes.append((method, re.compile(f"^{pattern}$"), fn.__name__))
            return fn
        return deco

    class Handler(BaseHTTPRequestHandler):
        server_version = "RagVulnDetect/" + VERSION

        def log_message(self, fmt, *args):
            if os.environ.get("RAGVULN_ACCESS_LOG"):
                super().log_message(fmt, *args)

        # ---- plumbing
        def _send(self, status, body, ctype="application/json", extra=None):
            raw = body if isinstance(body, bytes) else (body.encode("utf-8") if isinstance(body, str) else json.dumps(body).encode("utf-8"))
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(raw)

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                raise ApiError(413, "request too large")
            if n == 0:
                return {}
            if "application/json" not in (self.headers.get("Content-Type") or ""):
                raise ApiError(415, "Content-Type must be application/json")
            try:
                data = json.loads(self.rfile.read(n))
            except json.JSONDecodeError as e:
                raise ApiError(400, f"invalid JSON: {e}")
            if not isinstance(data, dict):
                raise ApiError(400, "JSON body must be an object")
            return data

        def _dispatch(self, method):
            try:
                host = (self.headers.get("Host") or "").rsplit(":", 1)[0] if not (self.headers.get("Host") or "").startswith("[") \
                    else (self.headers.get("Host") or "").split("]")[0] + "]"
                if host not in _LOCAL_HOSTS:
                    raise ApiError(403, "forbidden host")
                parsed = urlparse(self.path)
                path, query = parsed.path, {k: v[-1] for k, v in parse_qs(parsed.query).items()}
                if method in ("POST", "PATCH", "DELETE") and not path.startswith("/api/"):
                    raise ApiError(405, "method not allowed")
                if path.startswith("/api/"):
                    for m, rx, name in routes:
                        mt = rx.match(path)
                        if m == method and mt:
                            return getattr(self, name)(query, *mt.groups())
                    raise ApiError(404, "unknown endpoint")
                if method not in ("GET", "HEAD"):
                    raise ApiError(405, "method not allowed")
                return self._static(path)
            except ApiError as e:
                self._send(e.status, {"error": e.message})
            except Exception as e:  # noqa: BLE001
                if os.environ.get("RAGVULN_DEBUG"):
                    raise
                self._send(500, {"error": f"{type(e).__name__}: {e}"})

        do_GET = lambda self: self._dispatch("GET")          # noqa: E731
        do_HEAD = lambda self: self._dispatch("HEAD")        # noqa: E731
        do_POST = lambda self: self._dispatch("POST")        # noqa: E731
        do_PATCH = lambda self: self._dispatch("PATCH")      # noqa: E731
        do_DELETE = lambda self: self._dispatch("DELETE")    # noqa: E731

        def _static(self, path):
            if not os.path.isdir(DASHBOARD_DIST):
                return self._send(200, "<h1>Dashboard not built</h1><p>The API is running (see <a href='/api/health'>/api/health</a>). "
                                       "The prebuilt dashboard (dashboard/dist) is missing from this copy of the project.</p>", "text/html; charset=utf-8")
            rel = path.lstrip("/") or "index.html"
            full = os.path.realpath(os.path.join(DASHBOARD_DIST, rel))
            root = os.path.realpath(DASHBOARD_DIST)
            if not (full == root or full.startswith(root + os.sep)) or not os.path.isfile(full):
                full = os.path.join(root, "index.html")            # single-page-app fallback
            ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
            if full.endswith(".js"):
                ctype = "text/javascript"
            with open(full, "rb") as f:
                data = f.read()
            self._send(200, data, ctype + ("; charset=utf-8" if ctype.startswith("text/") else ""))

        # ---- endpoints
        @route("GET", "/api/health")
        def health(self, q):
            recs = load_kb_records()
            return self._send(200, {"ok": True, "version": VERSION, "kb_entries": len(recs),
                                    "llm_cache_entries": len(VerdictCache()), "llm": _llm_status(), "active_scan": mgr.active, "dashboard": os.path.isdir(DASHBOARD_DIST)})

        @route("POST", "/api/llm/test")
        def llm_test(self, q):
            self._body()
            try:
                p = providers.make_provider()
            except providers.LLMError as e:
                raise ApiError(400, str(e))
            if p is None:
                raise ApiError(400, "No LLM key configured. Add GROQ_API_KEY or GEMINI_API_KEY to .env (or paste it in Settings).")
            try:
                out = p.complete("Reply with the JSON object {\"ok\": true}", "ping", max_tokens=30)
            except providers.LLMError as e:
                raise ApiError(502, str(e))
            return self._send(200, {"ok": True, "provider": p.name, "model": p.model, "reply": out[:80]})

        @route("POST", "/api/llm/key")
        def llm_key(self, q):
            b = self._body()
            prov, key = str(b.get("provider", "")).lower(), str(b.get("key", "")).strip()
            if prov not in _KEY_ENV:
                raise ApiError(400, "provider must be 'groq' or 'gemini'")
            if len(key) < 12 or any(c.isspace() for c in key) or '"' in key or "'" in key:
                raise ApiError(400, "that does not look like an API key")
            _update_env_file(_KEY_ENV[prov], key)
            _update_env_file("LLM_PROVIDER", prov)
            os.environ[_KEY_ENV[prov]] = key
            os.environ["LLM_PROVIDER"] = prov
            os.environ.pop("LLM_MODEL", None)
            return self._send(200, {"ok": True, "llm": _llm_status()})

        @route("GET", "/api/knowledge-base")
        def kb(self, q):
            return self._send(200, {"entries": [{k: r.get(k) for k in ("standard", "tier", "cwe_id", "code", "name", "description", "owasp_category")}
                                                for r in load_kb_records()]})

        @route("GET", "/api/evaluation")
        def evaluation(self, q):
            out = {}
            for key, fname in (("retrieval", "retrieval_report.json"), ("llm", "llm_benchmark.json")):
                path = os.path.join(RESULTS_DIR, fname)
                try:
                    with open(path, encoding="utf-8") as f:
                        out[key] = json.load(f)
                except (OSError, json.JSONDecodeError):
                    out[key] = None
            out["kb_entries"] = len(load_kb_records())
            return self._send(200, out)

        @route("GET", "/api/scans")
        def scans(self, q):
            out = []
            for s in store.list_scans(db_path=mgr.db_path):
                s["by_status"] = store.count_by_status(scan_id=s["id"], db_path=mgr.db_path)
                s["message"] = mgr.messages.get(s["id"], "")
                out.append(s)
            return self._send(200, {"scans": out, "active": mgr.active})

        @route("POST", "/api/scans")
        def start_scan(self, q):
            b = self._body()
            source = str(b.get("source", "")).strip()
            if not source:
                raise ApiError(400, "source is required (a GitHub URL, a folder path, a .zip path, or 'demo')")
            if source.lower() == "demo":
                source = DEMO_APP
            elif source.lower() == "demo-languages":
                source = DEMO_APP_LANGS
            if not re.match(r"^(https?://|git@|ssh://)", source) and not os.path.exists(source):
                raise ApiError(400, f"'{source}' is not an existing folder/zip and not a repository URL")
            try:
                cfg = ScanConfig(
                    max_llm_chunks=max(1, min(int(b.get("max_llm_chunks", 40)), 500)),
                    use_rag=bool(b.get("use_rag", True)), skip_tests=bool(b.get("skip_tests", True)),
                    llm_mode=str(b.get("llm_mode", "auto")))
            except (TypeError, ValueError):
                raise ApiError(400, "max_llm_chunks must be a number")
            if cfg.llm_mode not in ("auto", "live", "replay"):
                raise ApiError(400, "llm_mode must be auto, live or replay")
            return self._send(202, {"scan_id": mgr.start(source, cfg)})

        @route("GET", r"/api/scans/(\d+)")
        def scan(self, q, sid):
            return self._send(200, _scan_view(mgr, int(sid)))

        @route("DELETE", r"/api/scans/(\d+)")
        def delete_scan(self, q, sid):
            if mgr.active == int(sid):
                raise ApiError(409, "scan is running; cancel it first")
            if not store.delete_scan(int(sid), db_path=mgr.db_path):
                raise ApiError(404, "scan not found")
            return self._send(200, {"deleted": int(sid)})

        @route("POST", r"/api/scans/(\d+)/cancel")
        def cancel(self, q, sid):
            if not mgr.cancel(int(sid)):
                raise ApiError(409, "scan is not running")
            return self._send(200, {"cancelling": int(sid)})

        def _filtered(self, sid, q):
            if not store.get_scan(int(sid), db_path=mgr.db_path):
                raise ApiError(404, "scan not found")
            rows = store.query_findings(scan_id=int(sid), order="severity", db_path=mgr.db_path)
            if not q.get("include_rejected") and not q.get("status"):
                rows = [r for r in rows if r.status != "rejected"]
            if q.get("status"):
                want = set(q["status"].split(","))
                rows = [r for r in rows if r.status in want]
            if q.get("severity"):
                want = set(q["severity"].split(","))
                rows = [r for r in rows if r.severity_band in want]
            if q.get("cwe"):
                rows = [r for r in rows if r.cwe_id == q["cwe"]]
            if q.get("triage"):
                rows = [r for r in rows if r.triage == q["triage"]]
            if q.get("q"):
                needle = q["q"].lower()
                rows = [r for r in rows if needle in f"{r.file_path} {r.chunk_name} {r.cwe_id} {r.llm_explanation}".lower()]
            return rows

        @route("GET", r"/api/scans/(\d+)/findings")
        def findings(self, q, sid):
            rows = self._filtered(sid, q)
            return self._send(200, {"findings": [_public_finding(r) for r in rows], "count": len(rows)})

        @route("GET", r"/api/scans/(\d+)/export")
        def export(self, q, sid):
            scan = _scan_view(mgr, int(sid))
            inc = set((q.get("include") or "confirmed,needs_review,unverified").split(","))
            rows = [r for r in store.query_findings(scan_id=int(sid), order="severity", db_path=mgr.db_path) if r.status in inc]
            fmt = q.get("format", "json")
            name = f"scan_{sid}_findings"
            if fmt == "csv":
                return self._send(200, exporters.findings_to_csv(rows), "text/csv; charset=utf-8",
                                  {"Content-Disposition": f'attachment; filename="{name}.csv"'})
            if fmt == "sarif":
                return self._send(200, json.dumps(exporters.findings_to_sarif(rows, scan), indent=2), "application/json",
                                  {"Content-Disposition": f'attachment; filename="{name}.sarif"'})
            if fmt == "json":
                return self._send(200, exporters.findings_to_json(rows, scan), "application/json",
                                  {"Content-Disposition": f'attachment; filename="{name}.json"'})
            raise ApiError(400, "format must be json, csv or sarif")

        @route("GET", r"/api/findings/(\d+)")
        def finding(self, q, fid):
            f = store.get_finding(int(fid), db_path=mgr.db_path)
            if not f:
                raise ApiError(404, "finding not found")
            return self._send(200, _public_finding(f, full=True))

        @route("POST", "/api/inspect")
        def inspect_post(self, q):
            from rag_vuln_detect.retrieval.inspect_view import inspect_code
            b = self._body()
            code = str(b.get("code", ""))
            if not code.strip():
                raise ApiError(400, "code is required")
            try:
                a = None if b.get("alpha") is None else min(1.0, max(0.0, float(b["alpha"])))
                be = None if b.get("beta") is None else min(5.0, max(0.0, float(b["beta"])))
                k = max(1, min(int(b.get("top_k", 6)), 20))
            except (TypeError, ValueError):
                raise ApiError(400, "alpha, beta and top_k must be numbers")
            lang = str(b.get("language") or "python").lower()
            return self._send(200, inspect_code(code, lang, alpha=a, beta=be, top_k=k))

        @route("GET", r"/api/findings/(\d+)/inspect")
        def finding_inspect(self, q, fid):
            from rag_vuln_detect.retrieval.inspect_view import inspect_code
            from rag_vuln_detect.ingestion.clone import _language_for
            from pathlib import Path
            f = store.get_finding(int(fid), db_path=mgr.db_path)
            if not f or not f.code:
                raise ApiError(404, "finding (with stored code) not found")
            lang = _language_for(Path(f.file_path))
            out = inspect_code(f.code, lang, file_path=f.file_path)
            out["finding"] = {"id": f.id, "file_path": f.file_path, "cwe_id": f.cwe_id, "chunk_name": f.chunk_name,
                              "stored_kb_context": f.retrieved_kb_context, "llm_vulnerable": f.llm_vulnerable,
                              "llm_model": f.llm_model}
            return self._send(200, out)

        @route("PATCH", r"/api/findings/(\d+)")
        def triage(self, q, fid):
            b = self._body()
            try:
                ok = store.set_triage(int(fid), str(b.get("triage", "")), (b.get("note") or None), db_path=mgr.db_path)
            except ValueError as e:
                raise ApiError(400, str(e))
            if not ok:
                raise ApiError(404, "finding not found")
            return self._send(200, _public_finding(store.get_finding(int(fid), db_path=mgr.db_path), full=True))

    return Handler


def create_server(host: str = "127.0.0.1", port: int = 8000, db_path: str | None = None) -> ThreadingHTTPServer:
    mgr = ScanManager(db_path or store._DEFAULT_DB_PATH)
    srv = ThreadingHTTPServer((host, port), make_handler(mgr))
    srv.manager = mgr  # type: ignore[attr-defined]
    return srv


def main() -> None:
    ap = argparse.ArgumentParser(description="RAG vulnerability scanner: API + dashboard")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--db", default=None, help="findings database path")
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()
    srv = create_server(args.host, args.port, args.db)
    url = f"http://{'localhost' if args.host in ('127.0.0.1', '0.0.0.0') else args.host}:{args.port}/"
    llm = _llm_status()
    print(f"RAG vulnerability scanner running at {url}")
    print("LLM:", f"{llm['provider']} ({llm['model']})" if llm.get("configured") else
          "not configured -> scans will produce UNVERIFIED candidates (add a free Groq/Gemini key in Settings)")
    print("Press Ctrl+C to stop.")
    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
