# Demo guide for the guide review ("100 % implementation – end-to-end demonstration")

Goal: show every approved module working together, stably, in about 8 minutes. Rehearse once with your key beforehand.

## Before the review (10 minutes)

1. `setup.bat`, then `run.bat`; add your free key in **Settings** and press **Test connection** (must say "Connected").
2. **Warm the cache once, online:** run `warm_demo.bat` (about 6-10 minutes on a free Gemini key, less on Groq). It scans both bundled demo apps (Python/JS and multi-language) and stores every LLM verdict in `data/llm_cache.jsonl`. From then on **Scan bundled demo app** and **Scan multi-language demo** replay those verdicts in seconds, so the live demo is fast and does not depend on the network or on rate limits. (The cache is keyed by the code, the retrieved context and the prompt; if you change any project file, warm it again.)
3. Keep a second browser tab on `http://localhost:8000/#/evaluation`. Run `run_evaluation.bat llm` beforehand so the LLM-vs-RAG table is filled in.
4. If the room has no internet: tick **Offline replay** on the scan page (never calls the API; it uses only cached verdicts). With `auto` (the default) cached verdicts are also used first, so a warmed demo needs no network either way.

## Live walk-through (maps to the rubric: all modules integrated, stable)

| Step | What you do | Module shown |
|---|---|---|
| 1 | Open the dashboard, point at the LLM status chip (provider/model) | LLM service |
| 2 | Click an example repo chip (or paste a GitHub URL, or **Demo app**). The live page shows the stage tracker (Fetch → Parse → Embed → Retrieve → Triage → Verify). **Candidates appear within seconds** (severity marked `?` = estimate from retrieval only), then each row flips to Confirmed / Needs review / Rejected as the LLM verifies it | ingestion, chunking, embedding, retrieval, LLM |
| 3 | Point at the severity strip, status tiles and the OWASP / CWE / file charts (click a CWE bar to filter the table) | severity scoring, findings store |
| 4 | Open a **Critical** finding: LLM explanation + evidence line, confidence, code with line numbers | LLM analysis |
| 5 | In the same drawer: *Retrieved knowledge* table (dense + BM25 scores, "✓" on the matching CWE) | dual-context retrieval, knowledge base |
| 6 | **Fix** tab: switch between **Fix for this code** (LLM, before/after diff, copy button) and **Standard pattern** (plain-language steps + an example in the file's language, 75+ weakness types) | remediation |
| 7 | Tick **Show rejected**: functions that look risky but the LLM judged safe (parameterised queries, escaping, allow-lists) | false-positive filtering |
| 8 | **Mark false positive / Accept** on a finding; export **SARIF** | findings store, interoperability |
| 9 | Optional: scan a real repo (`https://github.com/OWASP/NodeGoat`) | scalability, git-free ingestion |
| 9b | **Scan multi-language demo**: one insecure file each in Java, Kotlin, PHP, Go, C#, Ruby, C and Rust; findings carry the right CWE per language | multi-language support |
| 9c | On any finding press **Open in the retrieval inspector**: tokens with IDF weights, FAISS dense cosine, BM25 matches, the static rule that fired (rule id, regex, matched line), the fused ranking with live alpha/beta sliders, and the exact LLM prompt | retrieval transparency |
| 10 | **Knowledge base** page: filter the 269 entries (OWASP / CWE Top 25 / extended) and search by CWE or keyword | knowledge base |
| 11 | **Evaluation** page: retrieval across the five sets (dev, held-out, extended, fresh blind, other languages) and every method from dense-only to final; LLM-only vs LLM+RAG per split | final results |

## What to say about limitations (examiners value this)

- Retrieval alone is not enough: on the fresh blind set (61 snippets written after the rules were frozen) exact-match top-1 is 72.1 %, top-3 88.5 % and the right CWE is within the 6 entries the LLM sees for 93.4 %. The first release (without static rules) scored 42.6 % / 65.6 % / 80.3 % on the same set. All snippets and rules were written by the team, so state this as an optimistic estimate; the rest of the gap is taxonomy ambiguity (e.g. CWE-77 vs 78, CWE-327 vs 328 vs 916). That is why the LLM verdict step exists. If asked how the 72 % was reached, open the Inspector: it is rule evidence added to dense + BM25, not a tuned black box.
- Non-Python/JS languages are benchmarked on 67 pairs only (8-10 per language), and C++ reuses the C rules.
- Without a key the system degrades to labelled "unverified" candidates instead of pretending.
- Free-tier rate limits make big scans slow; the cache makes demos repeatable.
- Analysis is per function; cross-file issues need the LLM's lowered-confidence path / human review.
