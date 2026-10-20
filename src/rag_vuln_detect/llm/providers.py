"""
LLM provider clients (standard library only -- no extra packages to install).

Supported out of the box, all with free tiers:
  * Groq    (OpenAI-compatible chat completions)          GROQ_API_KEY
  * Gemini  (Google AI Studio generateContent REST API)   GEMINI_API_KEY / GOOGLE_API_KEY
  * Any OpenAI-compatible endpoint (OpenRouter, Ollama, OpenAI ...)
                                                           LLM_BASE_URL + LLM_API_KEY

Configuration is read from environment variables or a `.env` file in the
project root (see .env.example). Model names change over time, so unless
LLM_MODEL is set the client asks the provider for its model list and picks the
first entry from a preference list (`resolve_model`).

Network behaviour: HTTP 429/5xx and timeouts are retried with exponential
backoff (honouring Retry-After); authentication errors fail immediately; a
small token-bucket style limiter keeps free-tier requests-per-minute limits.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.error
import urllib.request

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


class LLMError(Exception):
    """Any failure talking to the LLM provider."""


class LLMAuthError(LLMError):
    """Invalid/missing API key (never retried)."""


# ---------------------------------------------------------------- configuration

def load_dotenv(path: str | None = None) -> None:
    """Minimal .env reader (KEY=VALUE per line, # comments); never overrides
    variables that are already set in the real environment."""
    path = path or os.path.join(PROJECT_ROOT, ".env")
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k and v and k not in os.environ:
                os.environ[k] = v


GROQ_BASE = "https://api.groq.com/openai/v1"
GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta"

GROQ_PREFERRED = [
    "llama-3.3-70b-versatile", "openai/gpt-oss-120b", "llama-3.1-70b-versatile",
    "openai/gpt-oss-20b", "llama-3.1-8b-instant",
]
GEMINI_PREFERRED = [
    "gemini-3.8-flash", "gemini-2.5-flash", "gemini-2.0-flash", "gemini-2.5-flash-lite", "gemini-flash-latest",
]
_NON_CHAT_HINTS = ("whisper", "tts", "guard", "embed", "playai", "orpheus", "imagen", "veo", "aqa", "vision",
                   "image", "live", "audio", "native", "robotics", "computer", "learnlm", "gemma", "moderation")


# ------------------------------------------------------------------ http helper

class RateLimiter:
    def __init__(self, requests_per_minute: float):
        self.base = 60.0 / max(requests_per_minute, 0.1)
        self.interval = self.base
        self._ok_streak = 0
        self._next = 0.0
        self._lock = threading.Lock()

    def speed_up(self, after: int = 4, factor: float = 1.3) -> None:
        """Called after a successful request. After a streak of successes, undo part of an earlier slow-down so a
        few 429s at the start of a scan do not leave the whole scan crawling at the slowest pace."""
        with self._lock:
            self._ok_streak += 1
            if self._ok_streak >= after and self.interval > self.base:
                self.interval = max(self.base, self.interval / factor)
                self._ok_streak = 0

    def slow_down(self, factor: float = 1.5, max_interval: float = 30.0) -> None:
        """Called after an HTTP 429: free tiers also limit tokens per minute, so spacing requests
        further apart is the only way to stay under a limit the client cannot see."""
        with self._lock:
            self._ok_streak = 0
            self.interval = min(self.interval * factor, max_interval)

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            delay = self._next - now
            self._next = max(now, self._next) + self.interval
        if delay > 0:
            time.sleep(delay)


def _http_json(url: str, headers: dict, payload: dict | None, timeout: float, method: str = "POST") -> dict:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Content-Type": "application/json", "User-Agent": "rag-vuln-detect/1.0", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _retry_hint(headers, body: str) -> float:
    """Seconds the server asked us to wait: Retry-After header, else 'try again in 6.5s / 1m3s / 800ms' in the body."""
    try:
        ra = headers.get("Retry-After") if headers else None
        if ra and float(ra) > 0:
            return float(ra)
    except (TypeError, ValueError):
        pass
    m = re.search(r"(?:try again|retry) in\s+(?:(\d+(?:\.\d+)?)\s*m(?!s))?\s*(?:(\d+(?:\.\d+)?)\s*s)?\s*(?:(\d+(?:\.\d+)?)\s*ms)?", body or "", re.I)
    if m and any(m.groups()):
        mins, secs, ms = (float(g) if g else 0.0 for g in m.groups())
        return mins * 60 + secs + ms / 1000
    return 0.0


def _daily_quota_exhausted(body: str) -> bool:
    """True when a 429 says the quota is gone for hours (free-tier per-day cap), so retrying is pointless."""
    b = (body or "").lower()
    if "perday" in b or "per day" in b or "tokens per day" in b:
        return True
    return re.search(r"retry in \d+h", b) is not None or re.search(r"try again in \d+h", b) is not None


def _request_with_retries(url: str, headers: dict, payload: dict | None, *, method: str = "POST",
                          timeout: float = 90, max_tries: int = 6, sleep=None, on_rate_limit=None) -> dict:
    sleep = sleep or time.sleep  # resolved at call time so tests can patch time.sleep
    last: Exception | None = None
    for attempt in range(max_tries):
        try:
            return _http_json(url, headers, payload, timeout, method)
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", "replace")[:1500]
            except Exception:
                pass
            if e.code in (401, 403):
                raise LLMAuthError(f"HTTP {e.code} from provider - check your API key. {body}") from e
            if e.code == 400:
                raise LLMError(f"HTTP 400 from provider: {body}") from e
            if e.code == 429 and _daily_quota_exhausted(body):
                raise LLMError(f"HTTP 429 daily quota exhausted for this model: {body}") from e
            if e.code == 429 or e.code >= 500:
                hint = _retry_hint(e.headers, body)
                # obey the server's own hint (plus a little margin) instead of a blind exponential backoff
                wait = min(hint + 0.5, 65) if hint else min(2 ** attempt * 3, 60)
                if e.code == 429 and on_rate_limit:
                    on_rate_limit()
                last = LLMError(f"HTTP {e.code}: {body}")
                sleep(wait)
                continue
            raise LLMError(f"HTTP {e.code}: {body}") from e
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last = LLMError(f"network error: {e}")
            sleep(min(2 ** attempt * 2, 20))
    raise last or LLMError("request failed")


# --------------------------------------------------------------------- providers

class Provider:
    name = "base"

    def __init__(self, api_key: str, model: str | None, base_url: str, rpm: float):
        self.api_key = api_key
        self._model = model
        self._pinned = bool(model)          # LLM_MODEL set explicitly: never switch away from it
        self._ranked: list[str] | None = None
        self._rejected: set[str] = set()
        self.base_url = base_url.rstrip("/")
        self.limiter = RateLimiter(rpm)
        self.calls = 0
        self.usage = {"prompt": 0, "completion": 0, "by_model": {}}      # tokens actually billed, from the API's own counts
        self._lock = threading.RLock()      # scans call complete() from several worker threads

    @property
    def model(self) -> str:
        if not self._model:
            with self._lock:
                if not self._model:
                    self._model = self.resolve_model()
        return self._model

    def list_models(self) -> list[str]:
        raise NotImplementedError

    def preferred(self) -> list[str]:
        return []

    def rank_models(self, available: list[str]) -> list[str]:
        """Order the provider's models best-first. Default: the static preference list, then the rest."""
        chat = [m for m in available if not any(h in m.lower() for h in _NON_CHAT_HINTS)]
        first = [p for p in self.preferred() if p in chat]
        return first + [m for m in chat if m not in first]

    def resolve_model(self) -> str:
        try:
            available = self.list_models()
        except LLMAuthError:
            raise
        except LLMError:
            available = []
        self._ranked = self.rank_models(available) or list(self.preferred())
        if not self._ranked:
            raise LLMError("could not determine a model; set LLM_MODEL")
        return self._ranked[0]

    def _switch_model(self, err: LLMError, failed_model: str | None = None) -> bool:
        """After a 'model not available' error, move to the next-best model. Returns True if the caller
        should retry (switched here, or another worker thread already switched away from `failed_model`)."""
        msg = str(err).lower()
        if self._pinned or not any(k in msg for k in ("404", "no longer available", "not found", "does not exist", "decommissioned", "daily quota exhausted")):
            return False
        with self._lock:
            if self._ranked is None:
                self.model  # noqa: B018 - populates the ranking
            if failed_model is not None and self._model != failed_model:
                return True                       # a concurrent request already moved on
            self._rejected.add(self._model)
            for m in self._ranked or []:
                if m not in self._rejected:
                    self._model = m
                    return True
        return False

    def _record_usage(self, data, model: str | None) -> None:
        """Add the API's reported token counts (OpenAI 'usage' or Gemini 'usageMetadata') to the running totals."""
        try:
            u = data.get("usage") or {}
            pt, ct = int(u.get("prompt_tokens") or 0), int(u.get("completion_tokens") or 0)
            if not (pt or ct):
                g = data.get("usageMetadata") or {}
                pt, ct = int(g.get("promptTokenCount") or 0), int(g.get("candidatesTokenCount") or 0) + int(g.get("thoughtsTokenCount") or 0)
        except (AttributeError, TypeError, ValueError):
            return
        with self._lock:
            self.usage["prompt"] += pt
            self.usage["completion"] += ct
            bm = self.usage["by_model"].setdefault(model or "?", {"calls": 0, "tokens": 0})
            bm["calls"] += 1
            bm["tokens"] += pt + ct

    def complete(self, system: str, user: str, max_tokens: int = 1200) -> str:
        """Request a completion, moving down the model ranking if the chosen model is unavailable."""
        while True:
            used = self.model
            try:
                return self._complete(system, user, max_tokens)
            except LLMAuthError:
                raise
            except LLMError as e:
                if not self._switch_model(e, failed_model=used):
                    raise

    def _complete(self, system: str, user: str, max_tokens: int) -> str:
        raise NotImplementedError


class OpenAICompatProvider(Provider):
    name = "openai-compatible"

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}

    def list_models(self) -> list[str]:
        data = _request_with_retries(f"{self.base_url}/models", self._headers(), None, method="GET", timeout=30, max_tries=2)
        return [m["id"] for m in data.get("data", []) if "id" in m]

    def _complete(self, system: str, user: str, max_tokens: int) -> str:
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": 0,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
        }
        if self.name == "groq" and "gpt-oss" in (self.model or "").lower():
            payload["reasoning_effort"] = "low"      # reasoning models otherwise spend most of the token budget thinking
        self.limiter.wait()
        self.calls += 1
        try:
            data = _request_with_retries(f"{self.base_url}/chat/completions", self._headers(), payload,
                                         on_rate_limit=self.limiter.slow_down)
        except LLMError as e:
            # some models/endpoints reject JSON mode: retry once without it
            msg = str(e).lower()
            if "400" in msg and ("response_format" in msg or "json" in msg or "reasoning" in msg):
                if "reasoning" in msg:
                    payload.pop("reasoning_effort", None)
                if "response_format" in msg or "json" in msg:
                    payload.pop("response_format", None)
                self.limiter.wait()
                data = _request_with_retries(f"{self.base_url}/chat/completions", self._headers(), payload,
                                             on_rate_limit=self.limiter.slow_down)
            else:
                raise
        self.limiter.speed_up()
        self._record_usage(data, payload.get("model"))
        try:
            return data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as e:
            raise LLMError(f"unexpected response shape: {str(data)[:200]}") from e


class GroqProvider(OpenAICompatProvider):
    name = "groq"

    def preferred(self) -> list[str]:
        return GROQ_PREFERRED


class GeminiProvider(Provider):
    name = "gemini"

    def _headers(self) -> dict:
        return {"x-goog-api-key": self.api_key}

    def preferred(self) -> list[str]:
        return GEMINI_PREFERRED

    def rank_models(self, available: list[str]) -> list[str]:
        """Newest stable 'flash' first (fast, free-tier friendly), then flash-lite, then pro.
        Model names change often and old ones get retired, so rank by version instead of a fixed list."""
        def key(name: str):
            m = re.search(r"gemini-(\d+(?:\.\d+)?)-(flash-lite|flash|pro)", name)
            if not m:
                return None
            tier = {"flash": 0, "flash-lite": 1, "pro": 2}[m.group(2)]
            unstable = any(t in name for t in ("preview", "exp", "-001", "thinking"))
            return (unstable, tier, -float(m.group(1)), name)
        chat = [m for m in available if not any(h in m.lower() for h in _NON_CHAT_HINTS)]
        scored = sorted((k, m) for m in chat if (k := key(m)) is not None)
        known = [m for _, m in scored]
        return known + [m for m in chat if m not in known]       # unrecognised names still usable, last

    def list_models(self) -> list[str]:
        data = _request_with_retries(f"{self.base_url}/models?pageSize=200", self._headers(), None, method="GET", timeout=30, max_tries=2)
        out = []
        for m in data.get("models", []):
            if "generateContent" in m.get("supportedGenerationMethods", []):
                out.append(m["name"].split("/", 1)[-1])
        return out

    def _complete(self, system: str, user: str, max_tokens: int) -> str:
        payload = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {"temperature": 0, "maxOutputTokens": max(max_tokens, 4096),
                                 "responseMimeType": "application/json"},
        }
        self.limiter.wait()
        self.calls += 1
        data = _request_with_retries(f"{self.base_url}/models/{self.model}:generateContent", self._headers(), payload,
                                     on_rate_limit=self.limiter.slow_down)
        self.limiter.speed_up()
        self._record_usage(data, self.model)
        try:
            parts = data["candidates"][0]["content"]["parts"]
            return "".join(p.get("text", "") for p in parts)
        except (KeyError, IndexError, TypeError) as e:
            raise LLMError(f"unexpected response shape: {str(data)[:200]}") from e


# ----------------------------------------------------------------------- factory

def make_provider() -> Provider | None:
    """Build the configured provider, or None when no key is configured."""
    load_dotenv()
    env = os.environ
    choice = (env.get("LLM_PROVIDER") or "").lower().strip()
    model = env.get("LLM_MODEL") or None
    rpm = env.get("LLM_RPM")

    def rpm_for(default: float) -> float:
        try:
            return float(rpm) if rpm else default
        except ValueError:
            return default

    if choice in ("", "auto"):
        if env.get("GROQ_API_KEY"):
            choice = "groq"
        elif env.get("GEMINI_API_KEY") or env.get("GOOGLE_API_KEY"):
            choice = "gemini"
        elif env.get("LLM_BASE_URL"):
            choice = "openai"
        else:
            return None
    if choice == "groq":
        key = env.get("GROQ_API_KEY")
        return GroqProvider(key, model, env.get("LLM_BASE_URL", GROQ_BASE), rpm_for(25)) if key else None
    if choice == "gemini":
        key = env.get("GEMINI_API_KEY") or env.get("GOOGLE_API_KEY")
        return GeminiProvider(key, model, env.get("LLM_BASE_URL", GEMINI_BASE), rpm_for(10)) if key else None
    if choice in ("openai", "openai-compatible", "ollama", "openrouter"):
        base = env.get("LLM_BASE_URL") or ("http://localhost:11434/v1" if choice == "ollama" else "https://api.openai.com/v1")
        return OpenAICompatProvider(env.get("LLM_API_KEY", ""), model, base, rpm_for(30))
    raise LLMError(f"unknown LLM_PROVIDER '{choice}' (use groq, gemini or openai)")
