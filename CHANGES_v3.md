# Release v3 - what changed, and how to go back

v3 is a separate copy of the project. Your v2 folder and v1 folder are untouched; each keeps its own `data/` (findings database
and LLM cache), `.env` (API key) and results. If anything in v3 misbehaves, keep using v2 (or v1). To try v3, unzip it into a NEW
folder, run `setup.bat`, then `run.bat`, and add your API key in Settings (keys are per folder).

| Area | v2 | v3 |
|---|---|---|
| Scan progress | progress bar, results after the LLM finishes | candidates listed seconds after the scan starts (status "Verifying"); each row turns Confirmed / Needs review / Rejected live; stage tracker with ETA |
| Remediation | 7 standard patterns (Python/JS syntax) + LLM fix | 38 patterns / 128 CWE ids with how-to steps and examples in the scanned file's language (up to 10 languages) + LLM fix |
| LLM quota handling | retried a "daily quota used up" error for minutes | detects it, skips to the next model at once (unless LLM_MODEL is pinned) |
| Dashboard | v2 look | new landing page with one-click example repos, severity + status tiles, clickable OWASP / CWE / file charts, finding panel with Overview / Fix / Evidence / Review tabs, copy button, dark and light themes, print stylesheet |
| Groq pacing | fixed spacing between calls, fixed back-off on 429 | reads the provider's "try again in Ns" / Retry-After and waits exactly that; call spacing recovers after successes instead of staying slow; gpt-oss models run with low reasoning effort (fewer tokens, so fewer limit hits) |
| Token counter | not shown | each scan shows tokens in / out and which models answered (read from the provider's own usage numbers); rejected rows say "Code reviewed" and "Why it was rejected" |
| Tests | 138 | 159 |

Not changed: retrieval (sink rules, hybrid fusion), the 12 supported languages, the benchmark numbers in `results/`, the Inspector,
and the SQLite schema (a v2 `findings.db` still opens; a v3 database has an extra `pending` status that only exists while a scan runs).

Honest limits: the v3 interface was exercised in a browser against a fake LLM, not a real one, and not on Windows; time to full
verification depends on your provider's rate limit (Groq free tier is the faster of the two free options).
