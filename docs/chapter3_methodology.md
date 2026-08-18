# Chapter 3: Proposed Methodology and System Design

## 3.1 Proposed Methodology

The system follows a ten-stage pipeline, refined from the initial proposal in light of the literature reviewed in Chapter 2 (in particular, the finding from L1/Vul-RAG that knowledge-level, cause-and-fix grounding outperforms raw code similarity, and from L9/L10 that CWE-specific prompting and static-analyzer-style context sharply reduce false positives):

1. **Repository submission.** The user submits a public GitHub repository URL through the web application.
2. **Repository ingestion.** The backend clones the repository (shallow clone for size efficiency) and extracts all source files, filtering out binaries, vendored/third-party directories (e.g., `node_modules`, `vendor`), and files above a size threshold.
3. **Source code parsing and chunking.** Each source file is parsed with a language-aware parser (tree-sitter, following the practice validated by RepoAudit, L2) and divided into logical chunks — functions, methods, or classes — rather than arbitrary line windows, preserving semantic boundaries.
4. **Embedding generation.** Each code chunk is converted into a vector embedding using a code-specialised embedding model and stored in a vector database, indexed per repository.
5. **Security knowledge base construction.** OWASP Top 10 and CWE documentation is separately chunked (by weakness/category) and embedded into a second, persistent vector collection shared across all scans — built once and reused, not rebuilt per repository.
6. **Dual-context retrieval.** For each code chunk under analysis, the system retrieves (a) semantically related code from the *same* repository (for cross-function/cross-file context, informed by L2/L11's finding that context improves both detection and localisation) and (b) the top-k most relevant OWASP/CWE entries from the knowledge base.
7. **LLM-based security analysis.** The code chunk plus both retrieved contexts are assembled into a structured, CWE-aware prompt (following the CWE-specific micro-rubric pattern shown effective in ZeroFalse, L9) and passed to the LLM, which returns a structured verdict: vulnerable/not vulnerable, mapped CWE-ID(s), natural-language explanation, and confidence.
8. **Severity scoring.** A custom, rule-based severity module — inspired by CVSS but not dependent solely on LLM judgment (per the AutoCVSS finding, L14, that pure-LLM severity scoring underperforms hybrid/rule-assisted scoring except in low-resource settings) — combines the CWE category's baseline severity with contextual signals (e.g., data exposure vs. denial-of-service class, presence of user-input reachability) to assign a severity band (Critical/High/Medium/Low).
9. **Remediation generation.** For confirmed findings, the LLM generates a proposed fix and a before/after code comparison, presented as a *suggestion for developer review* rather than an auto-applied patch — consistent with L17's finding that single-shot LLM patches need validation feedback before being trusted.
10. **Dashboard visualisation.** All findings are persisted and rendered on an interactive dashboard with search, filtering by severity/CWE/file, and drill-down into the explanation and suggested fix for each finding.

## 3.2 System Architecture

At a component level, the system is organised into five layers:

- **Presentation layer** — React.js single-page dashboard (repository submission form, scan-status view, results table with filters, per-finding detail view with before/after diff).
- **API layer** — Node.js/Express.js REST API mediating between the frontend, the ingestion/analysis pipeline, and the data stores.
- **Processing layer** — repository ingestion service, chunking service, embedding service, retrieval (RAG) orchestrator, and severity-scoring module (each implemented as a separable backend module/service to allow independent scaling and testing).
- **AI layer** — embedding model, vector database(s), and the LLM used for analysis and remediation generation.
- **Persistence layer** — MongoDB for scan metadata, findings, and user/session data; the vector database (FAISS/ChromaDB/Pinecone — see Section 3.5) for embeddings.

```
GitHub URL
    |
    v
[Repo Ingestion] --clone--> [Parsing & Chunking] --chunks--> [Embedding Model]
                                                                     |
                                                                     v
                                          [Vector DB: Repo Code Index] <---+
                                                                     |     |
[OWASP/CWE Docs] --> [Embedding Model] --> [Vector DB: Security KB]-+     |
                                                                     |     |
                                                    (per chunk) -----+     |
                                                                     v     |
                                                          [RAG Retrieval] -+
                                                                     |
                                                                     v
                                                        [LLM Security Analysis]
                                                          /            \
                                                         v              v
                                            [Severity Scoring]   [Remediation Gen.]
                                                         \              /
                                                          v            v
                                                     [MongoDB: Findings Store]
                                                                     |
                                                                     v
                                                     [React Dashboard: Search/Filter/Detail]
```

*(Figure 3.1 — this text schematic will be rendered as a formatted architecture diagram for the presentation; see attached slide deck / `design/architecture_diagram.png`.)*

## 3.3 Module Description

| Module | Responsibility | Key Design Choice | Literature Basis |
|---|---|---|---|
| Repository Ingestion | Clone and pre-filter a GitHub repo | Shallow clone, exclude vendored/binary paths | — |
| Parsing & Chunking | Split source into function/class-level units | Tree-sitter, language-aware, semantic boundaries (not fixed-length windows) | RepoAudit (L2) |
| Embedding Service | Convert code and KB text to vectors | Code-specialised embedding model, separate collections per repo vs. KB | Vul-RAG (L1) |
| Security Knowledge Base | Store OWASP Top 10 + CWE as retrievable knowledge | Built once, chunked by weakness category, versioned | Vul-RAG (L1) |
| RAG Retrieval Orchestrator | Fetch dual context (repo + KB) per chunk | Top-k retrieval from both collections, merged into one prompt context | Vul-RAG (L1), L11 |
| LLM Security Analysis | Classify vulnerability, map to CWE, explain | CWE-specific structured prompt/rubric, not one generic prompt | ZeroFalse (L9) |
| Severity Scoring | Assign a defensible severity band | Rule-based, CVSS-inspired, CWE-baseline + contextual modifiers — not LLM-only | AutoCVSS (L14) |
| Remediation Generation | Suggest a fix with before/after diff | Presented for developer review, not auto-applied | L17, L18 |
| Findings Store | Persist scan results | MongoDB collections: `scans`, `findings`, `repositories` | — |
| Dashboard | Visualise and triage findings | Search, filter by severity/CWE/file, per-finding drill-down | — |

## 3.4 Technology Stack

- **Frontend:** React.js, HTML, CSS, JavaScript.
- **Backend:** Node.js, Express.js.
- **Database:** MongoDB (findings, scan metadata, users).
- **Vector database:** FAISS (local/self-hosted, good for prototype-scale evaluation), with ChromaDB or Pinecone as managed/scale-out alternatives to be benchmarked during implementation.
- **AI components:** an LLM for analysis and remediation generation, a code-specialised embedding model, and a RAG orchestration layer.
- **Security standards:** OWASP Top 10, MITRE CWE, and a CVSS-inspired scoring rubric.
- **Version control:** Git/GitHub — used both as the subject of analysis (target repositories) and as the project's own source-control and documentation home (Section 3.8).

## 3.5 Feasibility, Risks, and Ethics

**Feasibility.** The core techniques (repository chunking, embedding-based retrieval, LLM-based classification) are individually well established and demonstrated at scale in the reviewed literature (L1, L2, L9, L10), which reduces technical risk; the main integration risk is combining dual-source retrieval (repo context + security KB) into a single coherent prompt without exceeding context limits, mitigated by top-k retrieval budgets and chunk-level (not whole-file) granularity.

**Key risks and mitigations:**

| Risk | Impact | Mitigation |
|---|---|---|
| LLM hallucinated or superficial findings (per L1's 0.06–0.14 baseline accuracy) | False findings undermine trust | Mandatory RAG grounding in OWASP/CWE KB; confidence field surfaced to user |
| Residual false positives despite RAG | Alert fatigue (per L10, baseline SAST FP rate 76–90%+) | CWE-specific structured prompting (L9); severity module deprioritises low-confidence/low-severity findings |
| Large repositories exceeding processing time/cost budget | Poor user experience, high LLM API cost | Chunk-level batching, caching of embeddings, configurable file/size filters |
| Auto-generated "fixes" being applied blindly | Could introduce new bugs (per L17) | Fixes always shown as a diff for manual developer review, never auto-committed |
| Analysing third-party/private code without consent | Ethical/legal concern | Public-repository scope only for this phase; explicit user submission required; no data retention beyond the scan session without consent |
| Knowledge base staleness (OWASP/CWE updates) | Missed newly catalogued weaknesses | Versioned knowledge base with a periodic re-embedding/update process |

**Ethical considerations.** The tool only analyses repositories the user explicitly submits; no unauthorised scanning is performed. Findings are explanatory and advisory — the system does not claim certainty, and severity/remediation output is clearly framed as a recommendation requiring developer judgment. Any use of third-party AI tools/models in building the system will be acknowledged in the final report per the course's academic-integrity guidelines.

## 3.6 Work Plan

| Phase | Target Review | Planned Deliverable |
|---|---|---|
| Requirement analysis, literature review, architecture & module design | Review 2 (19 Aug 2026) | This report (Ch. 1–3) + panel presentation |
| Repo ingestion + chunking + embedding pipeline; knowledge base construction (OWASP/CWE); ~50% of planned modules working | Review 3 (16 Sep 2026) | Functional ingestion-to-embedding pipeline demo |
| RAG retrieval + LLM analysis + severity scoring integrated end-to-end; initial dashboard | Draft Report Review / Review 4 (12–16 Oct 2026) | End-to-end working prototype, near-final report |
| Remediation generation, dashboard polish, testing/validation, final report | Review 5 (21 Oct 2026) | Final demonstration, complete report, viva |

Team responsibilities, detailed weekly milestones, and individual contribution allocation will be maintained as a living document (Section 3.8) and updated after every guide meeting, per the course's general guidelines on recording review comments and action taken.

## 3.7 Innovation

Unlike conventional AI code-review tools that either (a) apply an LLM directly to code with no external grounding, or (b) wrap a traditional static analyzer with no learned reasoning layer, the proposed system combines Retrieval-Augmented Generation over **two independent knowledge sources** — the target repository's own code (for context) and an external, standards-based security corpus (OWASP Top 10 + CWE, for grounding) — with a **transparent, rule-based severity layer** that does not depend solely on LLM judgment. This design is directly motivated by two literature findings: Vul-RAG (L1) showing knowledge-level RAG substantially outperforms ungrounded LLM judgment, and AutoCVSS (L14) showing pure-LLM severity scoring is not consistently reliable relative to rule-assisted approaches. The result is intended to be more reliable, transparent, and explainable than either static analysis or ungrounded LLM review alone.

## 3.8 Future Scope

- Support for additional programming languages beyond the initial prototype set.
- CI/CD pipeline integration for automated, continuous security scanning.
- IDE extensions for real-time, in-editor vulnerability detection.
- Pull-request-level security analysis (diff-aware scanning).
- Team collaboration and reporting features.
- Historical vulnerability tracking and trend analysis across repositories.
- Compliance reporting aligned with secure software development standards.
