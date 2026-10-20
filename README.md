# RAG Vulnerability Detection

**Find security weaknesses in source code, check each one with an LLM, and see exactly why it was flagged.**

A scanner for Python, JavaScript/TypeScript, Java, Kotlin, PHP, Go, C#, Ruby, C/C++ and Rust. It splits a repository into functions, retrieves the most relevant entries from an OWASP + CWE knowledge base, asks an LLM to judge each function against that evidence, then scores severity with fixed rules and proposes a fix. Everything is stored in a local database and shown in a web dashboard.

---

## Why it is different

| | |
|---|---|
| **Evidence first** | Retrieval and 435 regex sink rules propose candidates and reasons. A model only judges after that. |
| **Nothing hidden** | The Inspector page shows the dense, BM25, rule and prior score behind every ranked match. |
| **Honest failures** | Rejected findings are kept and counted. Anything the model could not check is labelled *Unverified*, never *Confirmed*. |
| **Repeatable severity** | Severity bands come from a fixed per-CWE table, not from the model. |
| **Runs anywhere** | Python only. No compiler, no GPU, no model download. A free Groq or Gemini key is optional. |

## Results

Does the correct CWE come back from a 269-entry knowledge base? Measured on 128 snippets written after the rules were frozen (61 Python/JS, 67 in eight other languages):

| Retriever | Top-1 | Top-6 |
|---|---|---|
| Dense (averaged GloVe) only | 17.2 % | 39.8 % |
| BM25 only | 46.9 % | 82.8 % |
| Sink rules only | 85.9 % | 95.3 % |
| **Full system** | **79.7 %** (95 % CI 71.9 to 85.7) | **96.9 %** |

The rules carry most of the accuracy. Dense and BM25 add recall: without BM25, top-6 drops from 96.9 % to 89.8 %. Every number above is reproduced by `run_evaluation.bat`.

Four real scans on the Groq free tier finished in 13 to 23 minutes and produced 100 confirmed findings in total (no ground truth exists for those targets, so this is a count, not an accuracy).

## Run it yourself

Anyone can run this on their own machine. It takes about five minutes, needs no account, and everything stays local.

**You need**

- Python 3.10 to 3.14 (check with `python --version`; on Linux and macOS it may be `python3`)
- Git, or just use *Code, Download ZIP* on this page
- Windows, Linux or macOS. No compiler, no GPU, no Node.js, no large downloads (the GloVe vectors ship with the repo)

**1. Get the code**

```bash
git clone https://github.com/aakashsivakumar20/RAG-vuln-detection.git
cd RAG-vuln-detection
```

**2. Install (once, about 1 to 2 minutes)**

| Windows | Linux / macOS |
|---|---|
| double-click `setup.bat`, or run it in a terminal | `./setup.sh` |

This creates a `.venv` folder, installs the pre-built packages from `requirements.txt`, and runs a self-check. It should end with `All checks passed.`

**3. Start the dashboard**

| Windows | Linux / macOS |
|---|---|
| `run.bat` | `./run.sh` |

Your browser opens on <http://127.0.0.1:8000>. If port 8000 is busy, start it with `--port 8001` (for example `./run.sh --port 8001`).

**4. Run a scan**

1. Open **New scan**.
2. Press **Scan bundled demo app** or **Scan multi-language demo**. Both work offline.
3. Or paste a public GitHub URL, a folder path, or upload a .zip of your own code.
4. Open **Results** to see findings, and **Inspector** to see why each entry ranked where it did. Findings can be exported as JSON, CSV or SARIF.

**5. Optional: add a free LLM key for verdicts**

Without a key the scan still runs, but every finding is labelled *Unverified*: it is a retrieval candidate that no model has checked. With a key, a model confirms or rejects each finding, assigns a severity band and writes a fix for your code.

- Get a free key from [Groq](https://console.groq.com/keys) (fast) or [Google Gemini](https://aistudio.google.com/apikey) (larger daily allowance). No credit card is needed for either.
- Paste it under **Settings, Save key, Test connection** in the dashboard. It is written to a local `.env` file that git ignores, so it is never uploaded.
- Free tiers are rate limited. A 40-unit scan took 13 to 23 minutes in our runs. Verdicts are cached in `data/llm_cache.jsonl`, so repeating a scan is fast.

**Terminal use**

```bash
# Windows
scan_cli.bat path\to\project            # or a .zip, or a GitHub URL

# Linux / macOS
PYTHONPATH=src .venv/bin/python -m rag_vuln_detect.pipeline.scan path/to/project
```

Useful flags: `--no-llm` (retrieval only), `--max-llm 20` (check fewer units), `--mode replay` (reuse cached verdicts, works offline), `--include-tests`.

**Check that your install works**

```bash
python check_setup.py            # add --llm to test your key (Linux/macOS: PYTHONPATH=src .venv/bin/python check_setup.py)
run_tests.bat                    # 159 automated tests (Linux/macOS: pip install -r requirements-dev.txt, then PYTHONPATH=src .venv/bin/python -m pytest -q src/tests)
run_evaluation.bat               # re-run the retrieval measurements in the Results section above
```

**If something goes wrong**

| Problem | Fix |
|---|---|
| `Python 3.10-3.14 not found` | Install Python from python.org and tick *Add to PATH* on Windows, then run setup again |
| pip tries to compile a package | Your Python is too old or too new; use a version between 3.10 and 3.14 |
| Page does not load | Use the exact address printed in the terminal; try `--port 8001` |
| Every finding says *Unverified* | No key is configured, or the key failed *Test connection* |
| Error 429 from the provider | You hit the free-tier limit. Wait, lower `--max-llm`, or switch provider |
| GitHub URL scan fails | The repository must be public and your machine needs internet access; try downloading the ZIP and scanning it instead |

To change the dashboard itself, install Node.js 18 or newer, then `cd dashboard && npm install && npm run build`. The built files in `dashboard/dist` are already included, so most users never need this.

## How a scan works

```
Repository -> Parse (tree-sitter) -> Embed (GloVe + IDF) -> FAISS indexes
           -> Hybrid retrieval (dense + BM25 + sink rules + prior) -> LLM verdict (JSON)
           -> Severity (CVSS bands) -> Fix suggestion -> SQLite -> Dashboard / SARIF / CSV / JSON
```

| # | Module | Code |
|---|---|---|
| 1 | Ingestion: GitHub URL, folder or zip, skips vendored and binary files | `ingestion/` |
| 2 | Parsing: function-level units for 12 languages | `chunking/` |
| 3 | Embedding: IDF-weighted averaged GloVe-100 | `embeddings/` |
| 4 | Vector stores: FAISS for the knowledge base and the scanned repo | `vectorstore/` |
| 5 | Knowledge base: 269 entries (OWASP Top 10:2025, CWE Top 25:2025, 234 more CWEs), 84 rubrics | `knowledge_base/` |
| 6 | Retrieval: min-max fused dense + BM25 + 435 rules + prior | `retrieval/` |
| 7 | LLM analysis: Groq, Gemini or any OpenAI-compatible API, cached | `llm/` |
| 8 | Severity: confirmed, needs review or rejected, plus a CVSS band | `severity/` |
| 9 | Remediation: 63 hand-written fix patterns (128 CWE ids) and the model's own fix | `remediation/` |
| 10 | Findings store, API and React dashboard; SARIF 2.1.0 export | `findings_store/`, `api/`, `dashboard/` |

Orchestration is in `pipeline/scan.py`. The built dashboard is in `dashboard/dist`; Node.js is only needed to change the UI (`cd dashboard && npm install && npm run build`).

## Repository layout

```
src/rag_vuln_detect/   the system, plus src/tests (159 tests)
dashboard/             React + Vite dashboard
demo/                  intentionally insecure sample apps for offline demos
evaluation/            labelled snippet sets and evaluation scripts
results/               saved measurements and charts
site/                  static project page published with GitHub Pages
docs/                  report chapters and demo guide
```

## Responsible use

Scan only code you own or have permission to test. The tool reads code and never changes it; fixes are proposals.
