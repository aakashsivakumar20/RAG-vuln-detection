# Session Log (Project Memory)

This file is the running memory for this project across chat sessions. At the start of any new session, read this file (and `README.md`) first to pick up where things left off. At the end of a working session, a new dated entry should be appended below (most recent entry at the top).

---

## 2026-09-14 (later) — Extended to 8/10 modules (Severity, Findings Store, Remediation)

**Context:** After the initial Review 3 push (5/10 modules, below), there was time before the panel date to do more real implementation. The user explicitly asked to build the additional work honestly rather than have it reported as less than it is — that instruction is recorded here because it shaped how this sprint's results are described everywhere (report, PPT, this log): as genuinely 8/10, including two disclosed technology substitutions, never rounded down.

**What was added (3 more of the 10 designed modules):**
- **Severity Scoring** (`src/rag_vuln_detect/severity/scorer.py`) — rule-based/CVSS-inspired, no substitution needed (this was always meant to be non-LLM per §3.3). Combines a per-CWE/per-OWASP-category reference severity table with a retrieval-confidence adjustment. The confidence signal is the *margin* between the top-1 and top-2 Security KB similarity scores, not the raw top-1 score — raw similarity was tried first and found uninformative (clusters ~0.85–0.95 regardless of correctness). The margin was calibrated empirically against the existing 22-snippet benchmark: mean margin 0.0424 when correct vs. 0.0094 when wrong; threshold set at 0.015. 10 tests, all passing.
- **Findings Store** (`src/rag_vuln_detect/findings_store/store.py`) — SQLite, a documented substitute for MongoDB: confirmed via `apt-cache search mongodb` that no server package is installable in this sandbox (only client bindings). Schema is document-shaped (JSON column for nested KB context) so a later MongoDB migration would be a straightforward mapping. 7 tests, all passing.
- **Remediation Generation** (`src/rag_vuln_detect/remediation/generator.py`) — template-based, CWE-keyed, a documented substitute for the originally-envisioned LLM-generated remediation (needs an LLM API this sandbox can't reach this sprint, same constraint as the embedding-model decision). Covers 7 of 25 CWE Top 25:2025 categories with a genuine before/after code pair and explanation each (SQLi, command injection, path traversal, insecure deserialization, XSS, code injection, unrestricted file upload); the other 18 categories explicitly return `None` rather than a guessed fix, since they need judgment about business logic/auth flow that only the LLM reasoning step can supply. 8 tests, all passing.
- **`pipeline/full_scan.py`** (new) wires all three onto the existing retrieval pipeline (Ingestion → Chunking → Embedding → KB → Retrieval → **Severity → Findings Store → Remediation**) and was run end-to-end against the same real repository as the initial sprint (OWASP/NodeGoat): 8 sampled chunks → 8 stored candidate findings (4 High, 3 Medium, 1 Low severity; 2/8 had a remediation template match). Output: `results/full_scan_report.json`.

**Honesty framing carried through everywhere (report, PPT, code docstrings, this log):** every finding produced by `full_scan.py` is a *candidate* — a code chunk paired with its nearest Security KB match, scored/stored/remediated as if it were a true positive. None of it is confirmed by the (still not-built) LLM Security Analysis module. This is stated explicitly in `severity/scorer.py`'s docstring, `docs/chapter4_implementation.md` §4.8, and on the new PPT slide — same discipline as the "candidate, not verified" language used throughout.

**Testing:** 25 new tests added (`src/tests/test_severity.py`, `test_findings_store.py`, `test_remediation.py`), full suite now 32/32 passing (was 7/7).

**Deliverables updated this session:**
- `docs/chapter4_implementation.md` — §4.1 module table updated to 8/10; new §4.8 (Severity/Findings Store/Remediation, with both substitutions disclosed); §4.5 updated to 32 tests; old §4.7 Limitations renumbered §4.9 and updated with the new candidate-findings/remediation-coverage points.
- `docs/Report_Ch1-4_RAG_VulnDetection.docx` rebuilt (24 → 26 pages) and visually verified page-by-page via LibreOffice→PDF→image conversion — all new content renders correctly. (Note: the PDF QA render substitutes "$" for "§" in section cross-references due to a headless-LibreOffice font-fallback quirk — confirmed by inspecting the actual docx XML that this is a QA-pipeline-only artifact, not a defect in the real .docx, which was independently confirmed via the PPTX's PDF export rendering "§" correctly.)
- `ppt/build_deck_review3.js` / `Review3_Panel_Presentation.pptx` — module-status slide (slide 4) updated to 8/10 with 3 new rows; new slide 8 ("Extending the Pipeline: Severity, Storage, Remediation"); testing slide updated to 32/32 with the new per-module test breakdown; limitations table (now slide 12) updated; closing stats updated. Now 13 slides (was 12). Visually verified slide-by-slide.
- `requirements.txt`, `src/README.md` updated — no new pip dependencies (sqlite3 is stdlib).

**Open items carried forward (unchanged from before this sprint, still outstanding):**
- [ ] Still need the actual Review 2 panel written feedback — `docs/chapter4_implementation.md` §4.6 placeholder remains.
- [ ] Review 4 priority order (stated on the new limitations slide/section): (1) LLM Security Analysis — the module that turns every candidate finding above into a verified one; (2) the embedding-model swap; (3) a minimal dashboard over the Findings Store.
- [ ] Remediation template coverage is 7/25 CWE categories; extending further is mechanical but the remaining categories mostly need the LLM reasoning step, not more templates.

**Next planned milestone:** Review 4 (Guide, 25 marks) + Draft Report Review (5 marks), 12–16 Oct 2026.

## 2026-09-14 — Review 3 implementation sprint ("at least 50% implementation")

**Context:** Panel Review 3 (20 marks) is scheduled for 16 Sep 2026. Rubric: Implementation (5), Technical Accuracy (5), Results Obtained So Far (5), Presentation and Clarity (5). Full rubric captured in `reference/review3_rubric.md`. The user explicitly asked for "at least 50 percent implementation of the project" — this meant writing real, running code, not just more documentation.

**What was built (5 of the 10 designed modules, chosen to match the exact Work Plan commitment in `docs/chapter3_methodology.md` §3.6):**
- **Repository Ingestion** (`src/rag_vuln_detect/ingestion/clone.py`) — clones a public GitHub repo, filters vendored/binary/oversized/unsupported-language files. Verified against a real repo, OWASP/NodeGoat: 90 files seen, 40 kept.
- **Parsing & Chunking** (`src/rag_vuln_detect/chunking/chunker.py`) — tree-sitter AST parsing, function/class-level chunks for Python/JS/TS, with a whole-file fallback. 40 files → 45 chunks on NodeGoat.
- **Embedding Service** (`src/rag_vuln_detect/embeddings/embedder.py`, `embeddings/idf.py`) — see the network-constraint story below.
- **Security Knowledge Base** (`src/rag_vuln_detect/knowledge_base/`) — 35 entries: OWASP Top 10:2025 + CWE Top 25:2025, fetched live from `top10.owasp.org` and `cwe.mitre.org`, each with rank/CWE-ID/description/example pattern. CWE→OWASP category mapping is documented as this project's own judgment, not an official crosswalk.
- **RAG Retrieval Orchestrator** (`src/rag_vuln_detect/pipeline/run_pipeline.py`) — wires ingestion → chunking → embedding → KB load → dual-context retrieval (repo code index + security KB index) end-to-end. Does **not** call an LLM — that's Review 4/5 scope.

**Key technical decision — implementation language:** the AI/RAG pipeline was implemented in **Python** (not the proposal's Node/Express), on the user's explicit go-ahead, framed as a microservice the eventual Node/Express API layer would call. Documented in `src/README.md`.

**Key technical decision — the embedding model, and a real debugged failure:** the sandbox's network policy blocks Hugging Face Hub and Stanford NLP's file host (confirmed via direct connection tests, not assumed) — where a code-specialised transformer (CodeBERT/UniXcoder/sentence-transformers) would normally be downloaded from. GitHub-hosted distribution was reachable, so the embedding service uses **IDF-weighted averaged GloVe word vectors** (`glove-wiki-gigaword-100` via `gensim`'s `gensim-data`), with camelCase/snake_case identifier splitting. This is a documented, swappable substitution confined to one module — not a workaround of the policy (huggingface.co was never touched again once the 403 was confirmed).
  - A first sanity check with plain averaging retrieved the wrong CWE (Path Traversal instead of SQL Injection) for a classic SQLi snippet. Root-caused to generic shared tokens diluting the average; fixed with IDF weighting. Measured the fix properly on a 22-snippet hand-labeled benchmark (`evaluation/`) rather than just asserting it worked: **top-1 accuracy rose from 54.5% to 63.6%** (top-3 unchanged at 72.7%). The remaining weak spot (access-control CWE family) is documented as the specific target for the Review 4 LLM reasoning step.
- 7 automated tests (`src/tests/test_pipeline.py`, pytest) all pass — chunker correctness, tokenizer, embedding normalisation, FAISS save/load round-trip, KB loading, SQLi retrieval.

**Deliverables produced this session:**
- `docs/chapter4_implementation.md` — new report chapter (Implementation Overview, the embedding-model decision, the real-repo run, the benchmark, testing, Review 2 feedback placeholder, limitations/next steps).
- `docs/master_report.md`, `docs/build_report.sh` updated to Review 3 / Chapters 1–4; rebuilt `docs/Report_Ch1-4_RAG_VulnDetection.docx` (24 pages) and **visually verified** page-by-page via LibreOffice→PDF→image conversion — all three new charts and the architecture diagram render correctly, no formatting regressions.
- `ppt/Review3_Panel_Presentation.pptx` — new 12-slide deck (`ppt/build_deck_review3.js`) matching the 4-part Review 3 rubric exactly (recap → scope → implementation walkthrough → technical-accuracy before/after story → results charts → testing → limitations/Review 4 plan). Visually verified slide-by-slide.
- `requirements.txt`, `src/README.md` documenting the real dependency set and the embedding-model substitution.
- All new code, docs, results, and the PPT committed and pushed to `github.com/aakashsivakumar20/RAG-vuln-detection`.

**Open items carried forward:**
- [ ] **Still need the actual Review 2 panel written feedback** — user said they'd paste it but hasn't yet. `docs/chapter4_implementation.md` §4.6 has a placeholder; fill this in and rebuild the docx (+ optionally add a PPT slide) as soon as it's provided.
- [ ] Decide which vector DB to use going forward — Review 3 code uses **FAISS** (`IndexFlatIP`), which effectively answers this for the prototype; update Chapter 3 §3.4 tech stack language if this is meant to be the final answer rather than one of three options.
- [ ] Review 4 (12–16 Oct 2026) scope: LLM Security Analysis + rule-based Severity Scoring integrated end-to-end, initial dashboard, Findings Store (MongoDB). The embedding-model swap (GloVe → code-specialised transformer, once reachable) should also be attempted then and re-benchmarked against this session's 63.6%/72.7% baseline.
- [ ] Chunking refinement noted but deferred: split `module.exports = function(){...}` CommonJS wrappers on inner method definitions (currently one large chunk).

**Next planned milestone:** Review 4 (Guide, 25 marks) + Draft Report Review (5 marks), 12–16 Oct 2026.

## 2026-08-18 (later) — Filled in team details

- Report and PPT title slides updated with real names: **Aakash Sivakumar (23BCE5119)** and **Udhay Anand Pandiyan (23BCE1793)**, guide **Jenila Livingston L M**. Both files regenerated and re-verified visually.
- Remaining open item from below: get the PPT approved by the guide before the panel review.

## 2026-08-18 — Review 2 prep sprint

**Context:** Panel Review 2 (20 marks) was scheduled for 19 Aug 2026, 11:45 AM–1:00 PM, offline, VIT Chennai. Rubric: domain/problem (3), literature review of 15+ recent papers (3), objectives/scope (2), methodology (3), architecture/module design (3), feasibility/risks/ethics/planning (3), report quality/presentation (3).

**What was done:**
- Reformatted the original one-page project proposal into a full report structure.
- Researched and reviewed 20 recent (2024–2026) papers across 4 themes: LLM/RAG-based vulnerability detection, false-positive reduction via LLM+static-analysis integration, automated CVSS/severity scoring, and automated repair/secure code generation. Full annotated list in `literature/annotated_bibliography.md`.
- Wrote Chapter 1 (Introduction), Chapter 2 (Literature Review), Chapter 3 (Methodology & System Design) — see `docs/`.
- Designed the system architecture (Graphviz) — `design/architecture.dot` / `architecture_diagram.png`. Five layers: presentation, API, processing, AI/retrieval, persistence.
- Built a 19-page supporting report `docs/Report_Ch1-3_RAG_VulnDetection.docx` (title page, abstract, TOC, Ch.1–3, architecture diagram appendix, references).
- Built a 16-slide panel presentation `ppt/Review2_Panel_Presentation.pptx` (Ocean/Midnight palette, matches the Review 2 rubric slide-by-slide).
- Extracted the official rubric/schedule from the guidelines PDF into `reference/review_schedule.md` for quick lookup at future reviews.
- Set up this repo as the persistent project home (this session cannot push to GitHub directly — no connector/credentials available — so the repo was built locally and handed to the user to push; see README for the one-time setup commands).

**Key design decisions made (carry these forward):**
- RAG grounds in **two** independent sources: the target repo's own code, and an external OWASP Top 10 + CWE knowledge base — not just historical CVE pairs.
- Severity scoring is **rule-based / CVSS-inspired**, not purely LLM-judged (justified by the AutoCVSS paper finding that pure-LLM severity scoring underperforms hybrid approaches).
- Remediation suggestions are always shown as a before/after diff for **developer review** — never auto-applied.
- Prototype scope (Project I) targets Python/JS first; multi-language, CI/CD, IDE, PR-level scanning are explicitly deferred to Project II (see Future Scope).
- Tech stack: React.js + Node/Express + MongoDB + FAISS/ChromaDB/Pinecone (undecided which vector DB yet — to benchmark during implementation).

**Open items / things the user still needs to fill in:**
- [x] Team member name(s) and registration number(s) — Aakash Sivakumar (23BCE5119), Udhay Anand Pandiyan (23BCE1793).
- [x] Project guide's name — Jenila Livingston L M.
- [ ] Get the PPT approved by the guide before the panel review (per HoD's email — mark entry only opens after guide approval in the portal).
- [ ] Team is confirmed at 2 members — leaves room for 1 more per the course's max-3 rule if needed later.
- [ ] Decide which vector DB (FAISS vs. ChromaDB vs. Pinecone) to actually implement first, ahead of Review 3.
- [ ] Push this repo to the user's own GitHub account (not yet done — see README "One-time GitHub setup").

**Next planned milestone:** Review 3 (16 Sep 2026) — needs a working ingestion → chunking → embedding pipeline and the OWASP/CWE knowledge base built, targeting ~50% of planned modules functional.


## 2026-10-12 — "Finish the project" sprint (report / PPT / paper deliberately NOT started)

**Context:** Pre-Final guide review window 12–16 Oct 2026 (VTOP deadline 21 Oct). Rubric items: 100 % implementation demo (10), final results (5), final PPT (5), journal-paper proof (5); draft report (5). Decision: finish a complete, working, downloadable system first; write report/PPT/paper afterwards from the real results.

**Built / changed**
- Installability: gensim removed; numpy GloVe loader + bundled float16 vocabulary (100k words, 19 MB; first built at 200k, cut to fit the 30 MB download limit - all results below were regenerated with the 100k table); all requirements have pre-built Windows wheels for Python 3.10–3.14. Verified by running the full test-suite in fresh Python 3.10, 3.13 and 3.14 environments.
- Retrieval: hybrid min-max fusion of dense cosine and BM25 over KB text + `kb_signals.json` (project-authored indicators); alpha=0.5 fitted on the DEV set only.
- Evaluation honesty: new 38-snippet held-out set. Review-3 dense retriever: 63.6 % dev top-1 with the full GloVe table in the Chapter 4 report (59.1 % with the shipped 100k table) vs 15.8 % held-out; final hybrid reaches 57.9 % held-out top-1 (top-3 68.4 %, MRR 0.647; recall@8 84 %, @10 95 %). Disclose this in the report; it motivates the LLM verdict stage. `results/retrieval_report.json`, `results/margin_calibration.json`.
- LLM Security Analysis module (`llm/`): provider-agnostic stdlib client (Groq, Gemini, OpenAI-compatible), runtime model discovery, retry/back-off, adaptive rate limiting, CWE micro-rubrics, structured JSON verdict, JSONL replay cache. No key is available in the build sandbox, so NO real LLM results exist yet; tests use a local fake server (`src/tests/mock_llm_server.py`) for plumbing only.
- Severity v2 (`score_verdict`): confirmed / needs_review / rejected from LLM verdict + confidence; retrieval-margin fallback (threshold 0.15, dev-calibrated) for unverified candidates.
- Findings store: scans table, LLM/remediation/triage columns, in-place migration of the old database.
- `pipeline/scan.py`: full end-to-end scan (all code units, LLM budget, rejected findings kept, no-LLM "unverified" degradation, cancel, progress). Ingestion accepts GitHub URL (git or git-free zip), local folder, .zip.
- Chunker splits oversized containers into nested units (JS constructor-style modules, big classes).
- API server (`api/server.py`, stdlib) + React dashboard (`dashboard/`, prebuilt): scan launcher with live progress, results with charts, finding drawer (verdict, retrieval table, before/after diff), triage, JSON/CSV/SARIF export, knowledge-base browser, Evaluation page, Settings (paste key, test connection).
- `evaluation/run_llm_benchmark.py`: LLM-only vs LLM+RAG on 60 vulnerable/patched pairs (pair accuracy with Wilson CI, FP rate, paired comparison) → `results/llm_benchmark.json`. **Must be run by the user with a real key before the Final Results review.**
- Demo target `demo/vulnerable_demo_app/`, Windows scripts (`setup.bat`, `run.bat`, ...), `check_setup.py`, README run guide, `docs/DEMO_GUIDE.md`.

**Open items**
- [ ] Run `run_evaluation.bat llm` with a real free key; record numbers (report Chapter 5, PPT, paper).
- [ ] Do one live demo scan with the key (fills `data/llm_cache.jsonl` for repeatable demos).
- [ ] Update Chapter 3/4 text for the changed design (hybrid retrieval, SQLite, GloVe via numpy, LLM provider choice).
- [ ] Final PPT, similarity report ≤ 15 %, guide-approved report, journal-paper submission proof.
- [ ] Not committed/pushed from this session.


## 2026-10-12 (later) — Knowledge base expansion and faster demo

**Why:** user asked for a much larger KB ("100s of entries") and a faster live demo.

**Built / changed**
- KB 35 -> **269 entries**: +234 extended CWEs (`kb_entries.json: cwe_extended`; source `knowledge_base/extended_source/extended_cwe.psv`, generator `generate_extended.py`, also writes `kb_signals.json` and `extended_severity.json`). CWE ids/names follow MITRE; descriptions, example patterns, indicators, severities and the OWASP mapping are project-authored. 84 CWEs now have LLM micro-rubrics (`llm/rubrics.json`). Severity scorer loads the extended table.
- Retrieval: code keywords / single letters / bare numbers no longer indexed (found with label-free `evaluation/hubness_check.py`); several generic indicator lists tightened; alpha rule changed to "closest to 0.5 within one dev snippet of the best" (fixed before looking at held-out; pure BM25 would have won by one dev snippet, which is noise at n=22) -> alpha 0.5.
- **Honest result:** held-out exact top-1 fell 57.9 % -> 39.5 % (top-3 55.3 %, top-6 60.5 %, top-10 71.0 %, near-miss top-1 52.6 %) because near-duplicate CWEs now compete; dev top-1 90.9 % -> 72.7 %. New 40-snippet blind **extended** set (e01-e40, 40 CWEs not in the old KB): top-1 57.5 %, top-6 95.0 %. Margin fallback is weaker (held-out confident precision 50 %); scorer docstring updated.
- LLM benchmark now 100 pairs (dev 22 + held-out 38 + extended 40) with per-split output; dashboard Evaluation and Knowledge pages updated.
- Speed: scans issue LLM requests with 4 worker threads (`ScanConfig.llm_workers`, `--workers`); provider model switching made thread-safe; rate limiter still caps requests/minute. `warm_demo.bat` pre-fills the verdict cache so the demo scan replays in seconds; dashboard "Offline replay" option, live confirmed/rejected counters during a scan, cache size shown.
- Tests: 117 passing (parallel speed-up and auth-abort tests, KB integrity test).

**Open items**
- [ ] User: run `warm_demo.bat` once with the key; run `run_evaluation.bat llm` for the 100-pair LLM numbers.
- [ ] Spot-check a sample of extended KB entries against cwe.mitre.org before quoting them in the report.
- [ ] Not committed/pushed from this session.


## 2026-10-14 — Release v2: static sink rules, Inspector page, 8 more languages

**Why:** user wanted (a) top-1 / top-3 retrieval accuracy "up by a lot", (b) to see everything in the dashboard (FAISS matching, IDF weighting), (c) more scanned languages, while keeping the original project as a fallback. v1 was left untouched (separate folder / zip); v2 is a separate tree.

**Retrieval**
- New `retrieval/patterns.py` + `knowledge_base/sink_rules.tsv` (207 Python/JS rules) + `sink_rules_other_langs.tsv` (228 rules for Java, Kotlin, PHP, Go, C#, Ruby, C/C++, Rust). Rule = regex tied to a CWE with weight, optional `requires` / `unless`; combined per CWE as noisy-or; whole-line comments stripped. Fused score: `alpha*dense_norm + (1-alpha)*bm25_norm + beta*rules + prior` (alpha 0.5 and beta 1.0 chosen on the dev set by rules fixed beforehand; prior 0.05 for OWASP/Top-25 entries was chosen after seeing the held-out set).
- New fresh blind set `heldout2` (61 snippets, 43 CWEs) written AFTER the rules were frozen; headline figure: top-1 72.1 % / top-3 88.5 % / top-6 93.4 % (v1 retriever on the same set 42.6 / 65.6 / 80.3). Held-out (seen once) 39.5 -> 57.9 top-1, 55.3 -> 73.7 top-3; extended 57.5 -> 80.0, 77.5 -> 97.5; dev 72.7 -> 90.9.
- Unit test caught a real rule bug (upper-case SQL keywords not matched); fixed; no benchmark number changed.
- Dense GloVe is weak on code (textbook SQLi ranks CWE-89 36th by dense alone); rules do most of the lifting. Neural embeddings untested (HuggingFace blocked in the sandbox).

**Languages**
- `ingestion/clone.py`: `LANGUAGE_BY_EXTENSION` (.java .kt .kts .php .go .cs .rb .c .h .cc .cpp .cxx .hpp .rs plus original). `chunking/chunker.py`: lazily imported optional grammars, method/function units, PHP top-level script chunk, name extraction via the `name` field / C declarators; missing grammar -> line windows. `requirements.txt` + `check_setup.py` updated (all grammar wheels exist for win_amd64, py3.10-3.14).
- New set `langs` (67 vulnerable/patched pairs, 8 languages; `evaluation/langs_snippets.json`). FIRST run, rules unedited: top-1 83.6 %, top-3 97.0 %, top-6 98.5 % (saved in `results/langs_first_run.json`); after fixing two rule gaps (PHP concatenated echo, Ruby `permit!`): 86.6 % / 100 %. v1 retriever on this set: 53.7 / 74.6.
- Demo: `demo/multilang_demo_app/` (one file per language), dashboard button "Scan multi-language demo" (`source: "demo-languages"`), `warm_demo.bat/.sh` warm both demos. Remediation "standard pattern" cards carry a note that the example is Python/JS syntax for other languages.

**Dashboard**
- New **Inspector** page (`#/inspector`, `#/inspector/finding/<id>`) backed by `POST /api/inspect` and `GET /api/findings/<id>/inspect` (`retrieval/inspect_view.py`): tokens with IDF share, BM25 tokens/doc frequencies, per-entry dense/BM25/rule/prior with live alpha/beta sliders, rule hits with regex and line, stored vs recomputed context, exact LLM prompt. Evaluation page redesigned for 5 sets and all configurations; finding drawer links to the Inspector.

**Tests:** 137 passing on Python 3.10, 3.13 and 3.14. LLM benchmark now 161 Python/JS pairs by default (+67 with `--splits ...,langs`).

**Open items**
- [ ] User: extract v2 into a NEW folder; run `setup.bat`, `warm_demo.bat` (cache keys changed because prompts changed), and later `run_evaluation.bat llm` (v1 install keeps its own results).
- [ ] Report / PPT / paper: quote the fresh-blind and langs figures with the honesty caveats in README.
- [ ] Not committed/pushed from this session.


## 2026-10-14 (later) - Live scan view, fix catalogue, UI redesign

**Why:** user's goal is a live demo: paste any GitHub repo, see which code is vulnerable, what the weakness is, a severity score and
a fix for each, in a clean UI, quickly. Free-tier LLM limits (Gemini: 20 requests/day on the default model) made verification slow
and showed that the app must not look empty while the LLM works.

- `providers.py`: a 429 saying the daily quota is gone (retry in hours) fails immediately and, unless LLM_MODEL is pinned, moves to
  the next model instead of retrying for minutes. Tests added.
- `pipeline/scan.py`: stores ranked retrieval candidates as `pending` right after retrieval; `store.replace_finding` updates each row
  when its verdict arrives; `store.finalize_pending` handles cancel/failure. `counts.triage_ready_s` records time to first results.
- `remediation/fix_catalog.py`: 38 patterns / 128 CWE ids with steps + per-language examples; `generate_remediation(cwe, language)`.
- API: `by_file`, `by_owasp`, `by_severity_estimated`, `elapsed_s` on the scan view.
- Dashboard: new styles, landing page, live results page, finding drawer with Fix tab, theme toggle.
- Verified in a browser (Playwright) against a throwaway fake LLM (kept in a temp cache; NOT a real result); 158 tests on 3.10 / 3.13 / 3.14.

**Open items**
- [ ] User: run v2 with a real key (Groq recommended); report the time to first results and time to full verification on a GitHub repo.
- [ ] Optional: batch several code units per LLM request to cut verification time (needs a benchmark to check accuracy).
- [ ] Not committed/pushed from this session.

**Release naming:** the live-view / fix-catalogue / UI work above is shipped as **v3** (folder and zip `rag-vuln-detect-project-v3`, API version 3.0.0), separate from v2, at the user's request so v2 stays as a fallback. See `CHANGES_v3.md`.

- Groq speed patch (v3): user's v2 scan with groq/openai/gpt-oss-120b took 13 min 34 s (23 confirmed / 2 review / 13 rejected, 38 requests). Likely cause: per-minute token limit + fixed back-off + limiter that never sped up again. Added Retry-After / "try again in" parsing, limiter recovery, low reasoning effort for gpt-oss on Groq. UNTESTED against real Groq (mock only); 158 tests on 3.10 / 3.13 / 3.14. Need user's timings from the v3 run.

- Groq usage read from user's console: ~155 requests / ~245K tokens on one model (~1,070 in + ~500 out per request) and ~39 requests / ~83K on the other; 285 calls total; the free tier is 8K tokens/min and 200K/day per model (organisation-wide, not per key), so a 38-unit scan needs 10-15 min and ~3 scans exhaust a model's day. gpt-oss-20b verdicts appeared on rows after the 120b daily cap was hit (model fallback). Added token counters (scan tiles: tokens in/out, models used) and "Code reviewed / Why it was rejected" labels; 159 tests on 3.10/3.13/3.14. Verdict cache key = prompt version + RAG flag + retrieved CWE ids + code (not key or model), failed calls not cached.

## >>> REMINDER FOR 15 OCT 2026 (user asked to be reminded) <<<
Visual features most likely to impress the panel (user wants big, visible things, not export/small stuff):
1. Repo risk map - files as boxes sized by code amount, coloured by worst severity; click opens that file's findings. (top pick; front-end only, uses existing scan data)
2. Repo grade (A-F / gauge) at the top of the results page, e.g. "Grade D: 8 critical, 10 high".
3. With-RAG vs without-RAG side-by-side for one finding (needs two cached scans: RAG on and off) - shows the dual-RAG value directly.
4. Live scan view (already built) - lead the demo with it, from cached results.
5. Fix preview diff (already built, Fix tab).
Rule: real scan data only, no decorative or faked visuals. Status: NOT STARTED, waiting for user "go".

Also still open: (a) user to check 2 more rejected NodeGoat rows, (b) install the small v3 patch (optional; token tile unwanted), (c) Groq daily limit reset -> run Demo app + NodeGoat once to fill cache, then use replay, (d) run `run_evaluation.bat llm --limit 20` then full LLM benchmark, (e) accuracy check against NodeGoat/DVWA known vulnerabilities, (f) report/PPT/paper only after project settled (VTOP deadline 21 Oct).
