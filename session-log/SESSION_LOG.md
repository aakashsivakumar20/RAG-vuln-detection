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
