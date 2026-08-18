# AI-Powered Secure Code Analysis and Vulnerability Detection using RAG

BCSE497J — Project I, VIT Chennai (SCOPE), Fall 2026–2027.

A web application that scans a GitHub repository for security vulnerabilities using Retrieval-Augmented Generation: code is chunked and embedded, an OWASP Top 10 + CWE knowledge base is embedded separately, and an LLM analyses each code chunk against both retrieved contexts to produce explainable, standards-referenced findings with a rule-based CVSS-inspired severity score and a suggested fix.

## How to resume work with Claude in a new session

1. Open a new chat and attach (or point Claude at) this repository.
2. Ask Claude to read `session-log/SESSION_LOG.md` first — that's the running memory of every decision made so far — then `README.md` and `reference/review_schedule.md` for the current deadline/rubric context.
3. At the end of the session, ask Claude to append a new dated entry to `session-log/SESSION_LOG.md` summarizing what changed, so the next session (yours or Claude's) doesn't lose context.

## Repository Structure

```
docs/                    Report chapters (Markdown) + the compiled .docx report
  proposal.md              Original one-page project proposal
  chapter1_introduction.md
  chapter2_literature_review.md
  chapter3_methodology.md
  master_report.md         Front matter (title page/abstract/TOC) that stitches the chapters together
  Report_Ch1-3_RAG_VulnDetection.docx   Compiled Review 2 supporting report

literature/               Literature review source material
  annotated_bibliography.md   All 20 reviewed papers with summaries, citations, and links

design/                   System architecture
  architecture.dot           Graphviz source
  architecture_diagram.png   Rendered diagram (used in the report and PPT)

ppt/                      Panel presentation
  Review2_Panel_Presentation.pptx
  build_deck.js             pptxgenjs script that generates the deck (edit + rerun `node build_deck.js`)
  gen_icons.js              Generates the icon PNGs used in the deck
  icon_*.png

reference/                 Course/administrative reference material
  BCSE497J_Project_I_Guidelines.pdf   Official guidelines, full review schedule & rubrics
  review_schedule.md                  Quick-reference extract of the schedule/rubrics

session-log/
  SESSION_LOG.md            Running memory — read this first in any new session
```

## Still to fill in

- Team member name(s) + registration number(s) (placeholders: `[Student Name(s)]`)
- Project guide's name (placeholder: `[Project Guide Name]`)
- See `session-log/SESSION_LOG.md` → "Open items" for the full list.

## One-time GitHub setup

This repo was built locally (the assistant session that created it had no GitHub credentials to push with). To make it your actual GitHub home:

```bash
cd rag-vuln-detect-project
git init                      # if not already a repo
git add -A
git commit -m "Initial project setup: Review 2 report, PPT, literature review, architecture"
# create an empty repo on github.com first (no README/license), then:
git remote add origin https://github.com/<your-username>/<repo-name>.git
git branch -M main
git push -u origin main
```

After that, either attach the repo's files to a future Claude session, or (if you use Claude Code / a git-aware environment) just point Claude at the cloned folder — either way, make sure Claude reads `session-log/SESSION_LOG.md` first.
