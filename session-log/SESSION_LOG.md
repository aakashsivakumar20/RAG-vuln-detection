# Session Log (Project Memory)

This file is the running memory for this project across chat sessions. At the start of any new session, read this file (and `README.md`) first to pick up where things left off. At the end of a working session, a new dated entry should be appended below (most recent entry at the top).

---

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
