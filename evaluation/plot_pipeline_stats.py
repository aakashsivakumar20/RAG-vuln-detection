"""
Turns results/pipeline_run_report.json (produced by pipeline/run_pipeline.py)
into two small charts for the Review 3 report/deck:
  - results/ingestion_funnel.png   (files seen -> kept vs. skipped reasons)
  - results/chunking_timing.png    (stage timing breakdown)
"""

from __future__ import annotations

import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

_HERE = os.path.dirname(os.path.abspath(__file__))
_RESULTS_DIR = os.path.join(_HERE, "..", "results")


def main():
    with open(os.path.join(_RESULTS_DIR, "pipeline_run_report.json")) as f:
        report = json.load(f)
    counts = report["counts"]
    timing = report["timing"]

    # --- Ingestion funnel ---
    labels = ["Kept\n(source files)", "Unsupported\nlanguage*", "Too\nlarge", "Binary /\nnon-source", "Vendored"]
    values = [
        counts["files_kept"],
        counts["files_skipped_unsupported_language"],
        counts["files_skipped_too_large"],
        counts["files_skipped_binary_or_nonsource"],
        counts["files_skipped_vendored"],
    ]
    colors = ["#065A82", "#9FB2CC", "#C7D6E8", "#C7D6E8", "#C7D6E8"]

    fig, ax = plt.subplots(figsize=(6.6, 4.0), dpi=150)
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")
    bars = ax.bar(labels, values, color=colors, width=0.6, zorder=3)
    for b in bars:
        h = b.get_height()
        ax.annotate(str(h), (b.get_x() + b.get_width() / 2, h), textcoords="offset points",
                    xytext=(0, 4), ha="center", fontsize=11, fontweight="bold", color="#21295C")
    ax.set_title(f"Repository Ingestion Funnel — {counts['files_seen']} files seen",
                 fontsize=12.5, fontweight="bold", color="#21295C")
    ax.set_ylabel("File count")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", color="#E4E9F0", linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    fig.text(0.01, -0.02, "*kept for a later phase (multi-language support), not an error", fontsize=8, color="#5B6472")
    fig.tight_layout()
    fig.savefig(os.path.join(_RESULTS_DIR, "ingestion_funnel.png"), bbox_inches="tight")

    # --- Stage timing ---
    stage_labels = ["Clone", "Chunk", "Embed"]
    stage_values = [timing["clone_seconds"], timing["chunk_seconds"], timing["embed_seconds"]]
    fig2, ax2 = plt.subplots(figsize=(5.6, 3.6), dpi=150)
    fig2.patch.set_facecolor("white")
    ax2.set_facecolor("white")
    bars2 = ax2.barh(stage_labels, stage_values, color=["#1C7293", "#065A82", "#21295C"], zorder=3)
    for b in bars2:
        w = b.get_width()
        ax2.annotate(f"{w:.2f}s", (w, b.get_y() + b.get_height() / 2), textcoords="offset points",
                     xytext=(6, 0), va="center", fontsize=11, fontweight="bold", color="#21295C")
    ax2.set_title(f"Pipeline Stage Timing — {counts['chunks_produced']} chunks total",
                  fontsize=12.5, fontweight="bold", color="#21295C")
    ax2.set_xlabel("Seconds")
    ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_visible(False)
    ax2.grid(axis="x", color="#E4E9F0", linewidth=0.8, zorder=0)
    ax2.set_axisbelow(True)
    fig2.tight_layout()
    fig2.savefig(os.path.join(_RESULTS_DIR, "chunking_timing.png"), bbox_inches="tight")

    print("Wrote ingestion_funnel.png and chunking_timing.png to results/")


if __name__ == "__main__":
    main()
