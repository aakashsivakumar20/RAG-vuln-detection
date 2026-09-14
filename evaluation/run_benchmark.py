"""
Retrieval-accuracy benchmark for the RAG Retrieval Orchestrator against the
Security Knowledge Base (Review 3 "Results Obtained So Far").

For each hand-labeled code snippet in benchmark_snippets.json, embeds it and
retrieves the top-3 nearest Security KB entries, then checks whether the
ground-truth CWE appears at rank 1 (top-1 accuracy) or anywhere in the top 3
(top-3 accuracy). Runs the comparison twice — plain averaging vs. the
IDF-weighted averaging described in embeddings/embedder.py — so the effect of
that refinement is a measured number, not a claim.

Outputs:
  results/benchmark_results.csv   - per-snippet detail
  results/benchmark_summary.json  - aggregate accuracy, both settings
  results/benchmark_accuracy.png  - bar chart, both settings
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from rag_vuln_detect.embeddings.embedder import embed_texts
from rag_vuln_detect.knowledge_base.build_kb import load_knowledge_base

_HERE = os.path.dirname(os.path.abspath(__file__))
_RESULTS_DIR = os.path.join(_HERE, "..", "results")


def _load_snippets() -> list[dict]:
    with open(os.path.join(_HERE, "benchmark_snippets.json")) as f:
        return json.load(f)["snippets"]


def _evaluate(snippets: list[dict], kb_index, idf, use_idf: bool) -> list[dict]:
    rows = []
    for s in snippets:
        vec, _ = embed_texts([s["code"]], idf=idf if use_idf else None)
        hits = kb_index.search(vec[0], top_k=3)
        labels = [h.get("cwe_id", h.get("code")) for h in hits]
        top1_correct = bool(labels) and labels[0] == s["expected_cwe"]
        top3_correct = s["expected_cwe"] in labels
        rows.append({
            "id": s["id"],
            "language": s["language"],
            "expected_cwe": s["expected_cwe"],
            "top3_predicted": ", ".join(labels),
            "top1_correct": top1_correct,
            "top3_correct": top3_correct,
            "weighting": "idf" if use_idf else "plain",
        })
    return rows


def run() -> dict:
    os.makedirs(_RESULTS_DIR, exist_ok=True)
    snippets = _load_snippets()
    kb_index, idf = load_knowledge_base()

    rows_plain = _evaluate(snippets, kb_index, idf, use_idf=False)
    rows_idf = _evaluate(snippets, kb_index, idf, use_idf=True)
    all_rows = rows_plain + rows_idf

    df = pd.DataFrame(all_rows)
    df.to_csv(os.path.join(_RESULTS_DIR, "benchmark_results.csv"), index=False)

    summary = {}
    for weighting, rows in (("plain", rows_plain), ("idf", rows_idf)):
        n = len(rows)
        top1 = sum(r["top1_correct"] for r in rows)
        top3 = sum(r["top3_correct"] for r in rows)
        summary[weighting] = {
            "n_snippets": n,
            "top1_accuracy": round(top1 / n, 3),
            "top3_accuracy": round(top3 / n, 3),
        }
    with open(os.path.join(_RESULTS_DIR, "benchmark_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    print(f"n={summary['plain']['n_snippets']} labeled snippets across "
          f"{len(set(s['expected_cwe'] for s in snippets))} distinct CWE categories\n")
    print(f"{'weighting':10s} {'top-1 acc':>10s} {'top-3 acc':>10s}")
    for weighting in ("plain", "idf"):
        s = summary[weighting]
        print(f"{weighting:10s} {s['top1_accuracy']:>10.1%} {s['top3_accuracy']:>10.1%}")

    _plot(summary)
    return summary


def _plot(summary: dict) -> None:
    labels = ["Top-1 accuracy", "Top-3 accuracy"]
    plain_vals = [summary["plain"]["top1_accuracy"], summary["plain"]["top3_accuracy"]]
    idf_vals = [summary["idf"]["top1_accuracy"], summary["idf"]["top3_accuracy"]]

    x = range(len(labels))
    width = 0.32

    fig, ax = plt.subplots(figsize=(6.4, 4.2), dpi=150)
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")

    bars1 = ax.bar([i - width / 2 for i in x], plain_vals, width, label="Plain averaging",
                   color="#9FB2CC")
    bars2 = ax.bar([i + width / 2 for i in x], idf_vals, width, label="IDF-weighted averaging",
                   color="#065A82")

    for bars in (bars1, bars2):
        for b in bars:
            h = b.get_height()
            ax.annotate(f"{h:.0%}", (b.get_x() + b.get_width() / 2, h),
                        textcoords="offset points", xytext=(0, 4),
                        ha="center", fontsize=10, color="#21295C", fontweight="bold")

    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, fontsize=11)
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("Accuracy against ground-truth CWE", fontsize=10.5)
    ax.set_title("KB Retrieval Accuracy on 22 Labeled Snippets", fontsize=13, fontweight="bold", color="#21295C")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(frameon=False, fontsize=9.5, loc="upper left")
    ax.grid(axis="y", color="#E4E9F0", linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)

    fig.tight_layout()
    out_path = os.path.join(_RESULTS_DIR, "benchmark_accuracy.png")
    fig.savefig(out_path)
    print(f"\nChart saved to {out_path}")


if __name__ == "__main__":
    run()
