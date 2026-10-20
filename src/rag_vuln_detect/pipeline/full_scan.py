"""
Legacy entry point kept for the Review 3/4 commands.

The retrieval-only "candidate findings" prototype that lived here has been superseded by
`pipeline/scan.py` (full pipeline including the LLM verdict step). This wrapper runs that
pipeline WITHOUT an LLM, which reproduces the old behaviour: top candidates are stored as
status "unverified" - retrieval matches, not confirmed vulnerabilities.

    python -m rag_vuln_detect.pipeline.full_scan [repo_url] [--sample N]
"""

from __future__ import annotations

import argparse

from rag_vuln_detect.llm.analyzer import SecurityAnalyzer
from rag_vuln_detect.pipeline.scan import ScanConfig, run_scan


def run(repo_url: str, sample_n: int = 8, db_path: str | None = None) -> dict:
    analyzer = SecurityAnalyzer(None, mode="live")      # no provider -> unverified candidates
    return run_scan(repo_url, ScanConfig(max_candidates_no_llm=sample_n), analyzer=analyzer, db_path=db_path)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo_url", nargs="?", default="https://github.com/OWASP/NodeGoat.git")
    ap.add_argument("--sample", type=int, default=8)
    a = ap.parse_args()
    res = run(a.repo_url, sample_n=a.sample)
    print(res["counts"])
