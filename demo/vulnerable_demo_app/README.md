# Vulnerable demo application (scan target)

A tiny, **intentionally insecure** web back-end written for this project so the scanner
can be demonstrated offline, without cloning anything from the internet.
Each module mixes vulnerable routines with their safe counterparts, so a good analyser
should flag the former and *not* flag the latter.

**Never run or deploy this code.** It is only ever read by the scanner.

| File | Intended content |
|------|------------------|
| `app/database.py` | SQL injection (concatenated / f-string queries) and parameterised queries |
| `app/system_tools.py` | OS command injection (`shell=True`, `os.system`) and safe argument-list calls |
| `app/files.py` | Path traversal on download/upload, plus a path-confined variant |
| `app/serialization.py` | Unsafe `pickle` / `yaml.load` / `eval` of untrusted data, plus safe variants |
| `app/web_views.py` | Reflected XSS via string-built HTML, plus escaped output |
| `app/accounts.py` | Missing authorization / IDOR on account access, plus owner-checked access |
| `app/fetcher.py` | SSRF in a URL fetcher, plus an allow-listed fetcher |
| `static_server/server.js` | Express handlers: SQLi, command injection, XSS, open redirect, safe versions |
| `static_server/session.js` | Weak session handling and hard-coded secrets |
