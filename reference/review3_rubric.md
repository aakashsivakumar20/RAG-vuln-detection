# BCSE497J — Review III (Panel Review), 16 Sep 2026

Source: HoD email, 14 Sep 2026. Offline, 11:45 AM – 1:00 PM, venue per Panel Allocation Sheet. PPT must be guide-approved before the review (mark entry opens only after guide approval in the portal). Any deviation from attending must be informed to the HoD before the scheduled time.

## Rubric (20 marks)

| Criterion | Descriptor | Marks |
|---|---|---|
| Implementation | Demonstrates working modules representing approximately half of the approved scope; the evidence is executable and attributable to the team. | 5 |
| Technical Accuracy | Uses technically correct methods, algorithms, parameters, and implementation practices consistent with the approved design. | 5 |
| Results Obtained So Far | Presents interim metrics, tables, graphs, or outputs and provides technically sound interpretation and comparison. | 5 |
| Presentation and Clarity | Explains the work logically, justifies decisions, and responds accurately to panel questions. | 5 |
| **Total** | | **20** |

## What "approximately half the approved scope" means here

Per `docs/chapter3_methodology.md` §3.6 Work Plan, the scope committed to for Review 3 was:

> "Repo ingestion + chunking + embedding pipeline; knowledge base construction (OWASP/CWE); ~50% of planned modules working"

Of the 10 modules in the design (§3.3), this maps to building and demonstrating, for real:

1. Repository Ingestion
2. Parsing & Chunking
3. Embedding Service
4. Security Knowledge Base (OWASP + CWE)
5. RAG Retrieval Orchestrator (dual-context retrieval, demonstrated quantitatively)

LLM Security Analysis, Severity Scoring, Remediation Generation, Findings Store (MongoDB), and the Dashboard remain planned for Review 4/5 and are **not** required to be working yet — this was scoped in Chapter 3 from the start, so it is not a change of plan.

## Note on the official full rubric (from the guidelines PDF)

The full course guidelines (`reference/BCSE497J_Project_I_Guidelines.pdf`, `reference/review_schedule.md`) list a more detailed 7-parameter Review 3 rubric (follow-up on Review 2 feedback, implementation, technical accuracy, interim results, problem-solving, report progress, presentation — each worth 2-3 marks, total 20). The HoD's email above condenses this into 4 categories; we address both by explicitly showing "action taken on Review 2 feedback" as part of Implementation/Presentation, in case the panel scores against the fuller rubric.
