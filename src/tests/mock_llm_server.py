"""
Local MOCK LLM server -- test infrastructure only.

Speaks the OpenAI-compatible (/models, /chat/completions) and the Gemini
(/models, /models/<m>:generateContent) wire formats so the provider clients,
retry logic, JSON handling, cache and the whole scan pipeline can be tested
offline. Its "verdicts" come from a few crude keyword rules and are NOT a model
of LLM quality: nothing produced through this server may be reported as a result
of the system (use a real free-tier key for that). The model name it advertises
is "mock-model" so any stored verdict is visibly marked.

Fault injection: push HTTP status codes / raw bodies onto `server.faults`; each
request pops one before normal handling.
"""
from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def crude_verdict(user_prompt: str) -> dict:
    """Very rough heuristic used only to exercise plumbing."""
    code = user_prompt.split("CODE CHUNK:", 1)[-1].split("RETRIEVED", 1)[0]
    safe_markers = ("?", "escape(", "parameterized", "execute(\"SELECT", "shell=False")
    if re.search(r"(execute|query)\s*\(\s*f?[\"'].*(\+|%s|\{).*", code) and "?" not in code.split("execute", 1)[-1][:60]:
        return {"vulnerable": True, "cwe_id": "CWE-89", "confidence": 0.9,
                "explanation": "User input is concatenated into a SQL string.",
                "evidence": "execute(... + ...)", "fix_summary": "Use a parameterised query.",
                "fixed_code": "cursor.execute('SELECT * FROM t WHERE id = ?', (uid,))"}
    if re.search(r"os\.system|subprocess\.[a-z]+\([^)]*shell\s*=\s*True", code):
        return {"vulnerable": True, "cwe_id": "CWE-78", "confidence": 0.85,
                "explanation": "Command string is built from input.", "evidence": "os.system(...)",
                "fix_summary": "Pass an argument list without a shell.", "fixed_code": "subprocess.run(args)"}
    return {"vulnerable": False, "cwe_id": None, "confidence": 0.8,
            "explanation": "No unsafe construct visible in this chunk.", "evidence": "",
            "fix_summary": "", "fixed_code": ""}


class MockLLMServer:
    def __init__(self, model="mock-model"):
        self.model = model
        self.extra_models: list[str] = []   # additional model ids advertised by /models
        self.retired: set[str] = set()      # models that answer 404 "no longer available"
        self.exhausted: set[str] = set()    # models that answer 429 "daily quota exhausted (retry in 10h)"
        self.faults: list = []       # ints (HTTP status) or str (raw 200 body)
        self.requests: list[dict] = []
        self.reply_override = None   # callable(user_prompt)->str | None
        self.latency = 0.0           # seconds each completion takes (simulates a slow model)
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # silence
                pass

            def _send(self, code, body, headers=None):
                raw = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _fault(self):
                if outer.faults:
                    f = outer.faults.pop(0)
                    if isinstance(f, tuple):   # (status, message)
                        self._send(f[0], {"error": {"message": f[1]}})
                        return True
                    if isinstance(f, int):
                        hdr = {"Retry-After": "0"} if f == 429 else {}
                        self._send(f, {"error": {"message": f"injected {f}"}}, hdr)
                        return True
                    self._send(200, f if isinstance(f, bytes) else str(f).encode())
                    return True
                return False

            def do_GET(self):
                outer.requests.append({"method": "GET", "path": self.path, "headers": dict(self.headers)})
                if self._fault():
                    return
                if self.path.startswith("/v1/models") or self.path.startswith("/models"):
                    self._send(200, {"data": [{"id": "whisper-large"}, {"id": outer.model}, *[{"id": m} for m in outer.extra_models]]})
                elif "/v1beta/models" in self.path:
                    self._send(200, {"models": [
                        {"name": "models/embedding-001", "supportedGenerationMethods": ["embedContent"]},
                        *[{"name": f"models/{m}", "supportedGenerationMethods": ["generateContent"]}
                          for m in [outer.model, *outer.extra_models]]]})
                else:
                    self._send(404, {"error": "not found"})

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(n) or b"{}")
                outer.requests.append({"method": "POST", "path": self.path, "payload": payload,
                                       "headers": dict(self.headers)})
                if self._fault():
                    return
                used = payload.get("model") or self.path.split("/models/")[-1].split(":")[0]
                if used in outer.exhausted:
                    self._send(429, {"error": {"code": 429, "status": "RESOURCE_EXHAUSTED", "message":
                               f"You exceeded your current quota. limit: 20, model: {used}\\nPlease retry in 10h27m23.2s."}})
                    return
                if used in outer.retired:
                    self._send(404, {"error": {"code": 404, "message": f"This model models/{used} is no longer available to new users.",
                                               "status": "NOT_FOUND"}})
                    return
                if outer.latency and (self.path.endswith("/chat/completions") or ":generateContent" in self.path):
                    threading.Event().wait(outer.latency)
                if self.path.endswith("/chat/completions"):
                    user = payload["messages"][-1]["content"]
                    text = outer._reply(user)
                    self._send(200, {"choices": [{"message": {"role": "assistant", "content": text}}], "usage": {"prompt_tokens": 1000, "completion_tokens": 200}})
                elif ":generateContent" in self.path:
                    user = payload["contents"][0]["parts"][0]["text"]
                    text = outer._reply(user)
                    self._send(200, {"candidates": [{"content": {"parts": [{"text": text}]}}], "usageMetadata": {"promptTokenCount": 900, "candidatesTokenCount": 100}})
                else:
                    self._send(404, {"error": "not found"})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=lambda: self.httpd.serve_forever(poll_interval=0.02), daemon=True)

    def _reply(self, user_prompt: str) -> str:
        if self.reply_override:
            return self.reply_override(user_prompt)
        return json.dumps(crude_verdict(user_prompt))

    @property
    def openai_base(self):
        return f"http://127.0.0.1:{self.port}/v1"

    @property
    def gemini_base(self):
        return f"http://127.0.0.1:{self.port}/v1beta"

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


if __name__ == "__main__":
    s = MockLLMServer().start()
    print("mock LLM on", s.openai_base)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        s.stop()
