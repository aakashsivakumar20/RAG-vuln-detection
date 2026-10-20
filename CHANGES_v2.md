# Release v2 — what changed, and how to go back to v1

v2 is a separate copy of the project. Your v1 folder (and `rag-vuln-detect-project-v1-fallback.zip`) is untouched; if anything in v2 misbehaves,
keep using v1. To try v2, unzip it into a NEW folder, run `setup.bat`, then `run.bat`.

| Area | v1 | v2 |
|---|---|---|
| Languages | Python, JavaScript, TypeScript | + Java, Kotlin, PHP, Go, C#, Ruby, C/C++, Rust |
| Retrieval signals | dense (GloVe+IDF) + BM25 + keyword indicators | + 435 static "dangerous API" rules + base-rate prior |
| Fresh blind retrieval set (61 snippets) top-1 / top-3 | 42.6 % / 65.6 % | 72.1 % / 88.5 % |
| Other-language set (67 pairs) top-1 / top-3 | 53.7 % / 74.6 % (v1 retriever) | 86.6 % / 100 % (first run before two rule fixes: 83.6 % / 97.0 %) |
| Dashboard | Scan / Knowledge base / Evaluation / Settings | + **Inspector** (FAISS, IDF, BM25, rules, fusion sliders, LLM prompt); multi-language demo button |
| Tests | 109 | 137 |

Python/JS behaviour: the original retrieval, chunking and rules for Python/JS/TS are unchanged apart from the added rule evidence; LLM verdict
caches from v1 do not carry over (the prompt now includes rule-fused rankings), so run `warm_demo.bat` once in the v2 folder.

Caveat: all snippets and rules were written by the same team; see README "Honest caveats".

## Patch 2026-10-14 (free-tier daily quota)
Gemini's free tier caps some models at ~20 requests/day. A "429 ... retry in 10h" is now treated as
"daily quota exhausted": no backoff retries, and (unless LLM_MODEL is pinned) the client moves to the
next-best model, each of which has its own quota. If every model is exhausted the scan stops with a clear
message. Per-minute 429s are still retried with backoff. 141 tests.

## Patch 2026-10-14 (live scan view, more fixes, new UI)
- **Instant triage:** the scan stores the ranked candidates right after retrieval (status `pending`, severity estimated from
  retrieval only, shown with `?`), then the LLM verifies them in priority order and each row is updated in place. The
  dashboard shows candidates after a few seconds and rows flip to Confirmed / Needs review / Rejected live. Cancelled or
  failed scans turn leftover `pending` rows into honest `unverified` ones.
- **Remediation catalogue:** `remediation/fix_catalog.py` - 38 patterns / 128 CWE ids (was 7), each with a plain-language
  step list, a reference and before/after examples in up to 10 languages (Python, JS, Java, Kotlin, PHP, Go, C#, Ruby, C, Rust).
  The example is chosen by the scanned file's language. The LLM's fix for the actual code is still shown beside it.
- **Dashboard redesign:** new landing page (paste a URL / one-click example repos), live stage tracker (Fetch, Parse, Embed,
  Retrieve, Triage, Verify) with ETA, live-updating findings table, severity + status tiles, OWASP / CWE / file charts that
  filter the table, finding panel with Overview / Fix / Evidence / Review tabs (copy button, up/down navigation), dark and
  light themes, print stylesheet. 152 tests.
