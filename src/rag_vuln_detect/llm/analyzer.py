"""
LLM Security Analysis module (Chapter 3, step 7).

For one code chunk, builds a CWE-aware prompt from the dual retrieval context
(the top matching OWASP/CWE knowledge-base entries with their micro-rubrics, and
similar code from the same repository), asks the LLM for a structured verdict and
validates it:

    {"vulnerable": bool, "cwe_id": "CWE-89"|null, "confidence": 0..1,
     "explanation": str, "evidence": str, "fix_summary": str, "fixed_code": str}

Design points
  * Retrieval is *grounding*, not the answer: the LLM may pick any CWE, and may
    decide the chunk is safe (this is how retrieval-only false positives are
    filtered out - see severity/scorer.py `score_verdict`).
  * Every verdict is cached on disk (data/llm_cache.jsonl). Modes:
        live    always call the provider (and refresh the cache)
        auto    use a cached verdict when present, otherwise call the provider
        replay  cache only - fully offline, deterministic (no provider needed)
  * No provider configured -> `analyze_chunk` returns a verdict with
    `status="unavailable"`; the pipeline keeps working and labels findings as
    unverified candidates.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import threading
import time

from rag_vuln_detect.llm.providers import LLMAuthError, LLMError, Provider

PROMPT_VERSION = "v1"
_HERE = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR = os.path.abspath(os.path.join(_HERE, "..", "..", "..", "data"))
DEFAULT_CACHE_PATH = os.path.join(_DATA_DIR, "llm_cache.jsonl")

MAX_CODE_CHARS = 6000
MAX_CONTEXT_SNIPPET_CHARS = 700

SYSTEM_PROMPT = (
    "You are a senior application-security reviewer. You examine ONE code chunk and decide whether it "
    "contains an exploitable security weakness.\n"
    "Rules:\n"
    "- Be precise. Code that already applies an effective safeguard (parameterised queries, output "
    "escaping, allow-list validation, an authorization check, a safe API) is NOT vulnerable. Do not invent "
    "problems in code that handles data safely, and do not flag a chunk only because it touches a sensitive area.\n"
    "- The retrieved security-standard entries are reference material: use their rubrics to judge, but "
    "choose the CWE that genuinely fits; you may choose a CWE that is not among the retrieved entries.\n"
    "- Judge only what is visible in the chunk (the rest of the application is not shown). If exploitability "
    "depends on code you cannot see, lower your confidence.\n"
    "- Reply with ONE JSON object and nothing else."
)

_JSON_SPEC = (
    'Return exactly this JSON object:\n'
    '{"vulnerable": true|false, "cwe_id": "CWE-<number>" or null, "confidence": <number 0.0-1.0>, '
    '"explanation": "<2-4 sentences: why it is or is not exploitable, naming the unsafe construct or the safeguard>", '
    '"evidence": "<the exact expression/line that is unsafe, or empty string>", '
    '"fix_summary": "<one sentence, empty string if not vulnerable>", '
    '"fixed_code": "<corrected version of the chunk, empty string if not vulnerable>"}'
)


@dataclasses.dataclass
class Verdict:
    status: str  # "ok" | "unavailable" | "error" | "not_cached"
    vulnerable: bool | None = None
    cwe_id: str | None = None
    confidence: float | None = None
    explanation: str = ""
    evidence: str = ""
    fix_summary: str = ""
    fixed_code: str = ""
    provider: str = ""
    model: str = ""
    cached: bool = False
    use_rag: bool = True
    error: str = ""

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


# ----------------------------------------------------------------------- rubrics

def load_rubrics() -> dict:
    with open(os.path.join(_HERE, "rubrics.json"), encoding="utf-8") as f:
        return {k: v for k, v in json.load(f).items() if not k.startswith("_")}


# ------------------------------------------------------------------------ prompt

def _clip(text: str, n: int) -> str:
    text = text.strip("\n")
    return text if len(text) <= n else text[:n] + "\n... [truncated]"


def build_prompt(code: str, *, file_path: str, language: str, kb_hits: list[dict] | None,
                 repo_context: list[dict] | None, rubrics: dict | None = None) -> tuple[str, str]:
    rubrics = rubrics if rubrics is not None else load_rubrics()
    parts = [f"FILE: {file_path}  (language: {language})", "", "CODE CHUNK:", "```", _clip(code, MAX_CODE_CHARS), "```", ""]
    if kb_hits:
        parts.append("RETRIEVED SECURITY KNOWLEDGE (most similar OWASP/CWE entries, best first):")
        for i, h in enumerate(kb_hits, 1):
            ident = h.get("cwe_id") or h.get("code") or h.get("id")
            parts.append(f"{i}. {ident} - {h.get('name', '')}")
            parts.append(f"   {h.get('description', '')}")
            rb = rubrics.get(h.get("cwe_id") or "")
            if rb:
                parts.append(f"   Vulnerable when: {rb['vulnerable_when']}.")
                parts.append(f"   Safe when: {rb['safe_when']}.")
        parts.append("")
    if repo_context:
        parts.append("SIMILAR CODE FROM THE SAME REPOSITORY (context only, not under review):")
        for c in repo_context:
            parts.append(f"- {c.get('path', '')} :: {c.get('name', '')} (lines {c.get('lines', '')})")
            if c.get("code"):
                parts.append("```")
                parts.append(_clip(c["code"], MAX_CONTEXT_SNIPPET_CHARS))
                parts.append("```")
        parts.append("")
    parts.append(_JSON_SPEC)
    return SYSTEM_PROMPT, "\n".join(parts)


# ----------------------------------------------------------------------- parsing

_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.I)
_CWE_RE = re.compile(r"(?:CWE[-\s_:]*)?(\d{1,5})", re.I)


def extract_json(text: str) -> dict:
    text = _FENCE_RE.sub("", (text or "").strip()).strip()
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        if start < 0:
            raise ValueError("no JSON object in reply")
        depth, in_str, esc = 0, False, False
        end = None
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end is None:
            raise ValueError("unterminated JSON object")
        obj = json.loads(text[start:end])
    if not isinstance(obj, dict):
        raise ValueError("JSON reply is not an object")
    return obj


def normalise_cwe(value) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    if not s or s.lower() in ("null", "none", "n/a", "unknown"):
        return None
    m = _CWE_RE.search(s)
    return f"CWE-{int(m.group(1))}" if m else None


def parse_verdict(text: str) -> Verdict:
    obj = extract_json(text)
    vuln = obj.get("vulnerable")
    if isinstance(vuln, str):
        vuln = vuln.strip().lower() in ("true", "yes", "vulnerable")
    if not isinstance(vuln, bool):
        raise ValueError("missing boolean 'vulnerable'")
    try:
        conf = float(obj.get("confidence", 0.5))
    except (TypeError, ValueError):
        conf = 0.5
    conf = max(0.0, min(1.0, conf))
    cwe = normalise_cwe(obj.get("cwe_id")) if vuln else None
    return Verdict(
        status="ok", vulnerable=vuln, cwe_id=cwe, confidence=round(conf, 3),
        explanation=str(obj.get("explanation") or "").strip(),
        evidence=str(obj.get("evidence") or "").strip(),
        fix_summary=str(obj.get("fix_summary") or "").strip() if vuln else "",
        fixed_code=str(obj.get("fixed_code") or "").strip("\n") if vuln else "",
    )


# ------------------------------------------------------------------------- cache

class VerdictCache:
    """Append-only JSONL cache keyed by a hash of (prompt version, RAG mode, code, context ids)."""

    def __init__(self, path: str | None = None):
        # RAGVULN_LLM_CACHE lets tests / experiments use a separate cache file
        path = path or os.environ.get("RAGVULN_LLM_CACHE") or DEFAULT_CACHE_PATH
        self.path = path
        self._lock = threading.Lock()
        self._entries: dict[str, dict] = {}
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        self._entries[rec["key"]] = rec
                    except (json.JSONDecodeError, KeyError):
                        continue

    @staticmethod
    def make_key(code: str, kb_ids: list[str], use_rag: bool) -> str:
        h = hashlib.sha256()
        h.update(f"{PROMPT_VERSION}|{int(use_rag)}|{','.join(kb_ids)}|".encode())
        h.update(code.encode("utf-8", "replace"))
        return h.hexdigest()[:24]

    def get(self, key: str) -> Verdict | None:
        rec = self._entries.get(key)
        if not rec:
            return None
        v = Verdict(**rec["verdict"])
        v.cached = True
        return v

    def put(self, key: str, verdict: Verdict) -> None:
        rec = {"key": key, "saved_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "verdict": verdict.to_dict()}
        with self._lock:
            self._entries[key] = rec
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")

    def __len__(self) -> int:
        return len(self._entries)


# ---------------------------------------------------------------------- analyzer

class SecurityAnalyzer:
    def __init__(self, provider: Provider | None, mode: str = "auto",
                 cache: VerdictCache | None = None, use_cache: bool = True):
        if mode not in ("live", "auto", "replay"):
            raise ValueError("mode must be live, auto or replay")
        self.provider = provider
        self.mode = mode
        self.cache = cache if cache is not None else (VerdictCache() if use_cache else None)
        self.rubrics = load_rubrics()
        self.stats = {"calls": 0, "cache_hits": 0, "errors": 0, "unavailable": 0}
        self._stats_lock = threading.Lock()

    def _bump(self, key: str) -> None:
        with self._stats_lock:
            self.stats[key] += 1

    @property
    def available(self) -> bool:
        return self.mode == "replay" or self.provider is not None

    def describe(self) -> str:
        if self.provider:
            try:
                model = self.provider.model
            except LLMError:
                model = "unknown model"
            return f"{self.provider.name} / {model} (mode={self.mode})"
        return f"no provider configured (mode={self.mode})"

    def analyze(self, code: str, *, file_path: str = "", language: str = "",
                kb_hits: list[dict] | None = None, repo_context: list[dict] | None = None,
                use_rag: bool = True) -> Verdict:
        kb_ids = [h.get("cwe_id") or h.get("code") or "" for h in (kb_hits or [])] if use_rag else []
        key = VerdictCache.make_key(code, kb_ids, use_rag)

        if self.cache is not None and self.mode in ("auto", "replay"):
            hit = self.cache.get(key)
            if hit:
                self._bump("cache_hits")
                hit.use_rag = use_rag
                return hit
        if self.mode == "replay":
            return Verdict(status="not_cached", use_rag=use_rag,
                           error="no cached verdict for this chunk (replay mode)")
        if self.provider is None:
            self._bump("unavailable")
            return Verdict(status="unavailable", use_rag=use_rag,
                           error="no LLM provider configured (set GROQ_API_KEY or GEMINI_API_KEY)")

        system, user = build_prompt(code, file_path=file_path, language=language,
                                    kb_hits=kb_hits if use_rag else None,
                                    repo_context=repo_context if use_rag else None,
                                    rubrics=self.rubrics)
        last_err = ""
        for attempt in range(2):
            try:
                self._bump("calls")
                text = self.provider.complete(system, user)
                verdict = parse_verdict(text)
                verdict.provider, verdict.model, verdict.use_rag = self.provider.name, self.provider.model, use_rag
                if self.cache is not None:
                    self.cache.put(key, verdict)
                return verdict
            except LLMAuthError as e:
                self._bump("errors")
                return Verdict(status="error", use_rag=use_rag, error=str(e))
            except (ValueError, json.JSONDecodeError) as e:
                last_err = f"unparseable model reply: {e}"
                user = user + "\n\nYour previous reply was not valid JSON. Reply with ONLY the JSON object."
            except LLMError as e:
                last_err = str(e)
                break
        self._bump("errors")
        return Verdict(status="error", use_rag=use_rag, error=last_err)
