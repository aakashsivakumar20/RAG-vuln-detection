"""
Final retrieval report: dense baselines vs. hybrid retrieval, on the DEV set
(used for fitting alpha) and the untouched HELD-OUT set (generalisation).

Writes results/retrieval_report.json, results/retrieval_report.csv and
results/retrieval_comparison.png.
"""
from retrieval_eval import *  # noqa
import csv

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

_RESULTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")


def run() -> dict:
    kb_index, idf = load_knowledge_base()
    configs = {
        "Dense, plain average": dense_rank_fn(kb_index, idf, False),
        "Dense, IDF-weighted (Review 3)": dense_rank_fn(kb_index, idf, True),
        "Hybrid, KB text only": hybrid_rank_fn(HybridRetriever(kb_index, idf, use_signals=False, use_rules=False, prior=0.0), beta=0.0),
        "Hybrid + signals (v1 retriever)": hybrid_rank_fn(HybridRetriever(kb_index, idf, use_signals=True, use_rules=False, prior=0.0), beta=0.0),
        "Hybrid + signals + sink rules (final)": hybrid_rank_fn(HybridRetriever(kb_index, idf, use_signals=True)),
    }
    out: dict = {"alpha": HybridRetriever(kb_index, idf).alpha, "sets": {}}
    per_snippet = []
    for set_name in ("dev", "heldout", "extended", "heldout2", "langs"):
        snippets = load_set(set_name)
        out["sets"][set_name] = {"n": len(snippets), "configs": {}}
        for cname, fn in configs.items():
            rows = ranks_for(snippets, fn, k=10)
            m = {**metrics(rows), **family_metrics(rows)}
            out["sets"][set_name]["configs"][cname] = {k: round(v, 4) if isinstance(v, float) else v for k, v in m.items()}
            for r in rows:
                per_snippet.append({"set": set_name, "config": cname, "id": r["id"], "expected": r["expected"],
                                    "top5": " ".join(r["pred"][:5]), "rank": r["rank"] or ""})
    # per-language breakdown of the final retriever on the v2 language set
    langs = load_set("langs")
    rows = ranks_for(langs, configs["Hybrid + signals + sink rules (final)"], k=10)
    by: dict = {}
    for s_, r_ in zip(langs, rows):
        by.setdefault(s_["language"], []).append(r_)
    out["langs_by_language"] = {l: {k: round(v, 4) if isinstance(v, float) else v for k, v in metrics(rs).items()}
                                for l, rs in by.items()}
    with open(os.path.join(_RESULTS, "retrieval_report.json"), "w") as f:
        json.dump(out, f, indent=2)
    with open(os.path.join(_RESULTS, "retrieval_report.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(per_snippet[0].keys()))
        w.writeheader(); w.writerows(per_snippet)
    for set_name, data in out["sets"].items():
        print(f"\n== {set_name} (n={data['n']}) ==")
        for cname, m in data["configs"].items():
            print(f"  {cname:34s} top1={m['top1']:.1%} top3={m['top3']:.1%} top5={m['top5']:.1%} top6={m['top6']:.1%} top10={m['top10']:.1%} MRR={m['mrr']:.3f}  [family top1={m.get('family_top1', 0):.1%} top3={m.get('family_top3', 0):.1%}]")
    _plot(out)
    return out


def _plot(out):
    names = list(next(iter(out["sets"].values()))["configs"].keys())
    colors = ["#C9D3E3", "#9FB2CC", "#5A9BB8", "#1C7293", "#21295C"]
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.4), dpi=150, sharey=True)
    for ax, (set_name, title) in zip(axes, (("heldout2", "Fresh blind set (written after rules frozen)"), ("heldout", "Held-out set (seen once; prior chosen after)"))):
        data = out["sets"][set_name]["configs"]
        x = range(3)
        w = 0.16
        for j, n in enumerate(names):
            vals = [data[n]["top1"], data[n]["top3"], data[n]["top5"]]
            bars = ax.bar([i + (j - 2) * w for i in x], vals, w, label=n, color=colors[j])
            for b in bars:
                ax.annotate(f"{b.get_height():.0%}", (b.get_x() + b.get_width() / 2, b.get_height()),
                            textcoords="offset points", xytext=(0, 2), ha="center", fontsize=6.5, color="#21295C")
        ax.set_xticks(list(x)); ax.set_xticklabels(["Top-1", "Top-3", "Top-5"])
        ax.set_ylim(0, 1.12); ax.set_title(f"{title}, n={out['sets'][set_name]['n']}", fontsize=10.5, color="#21295C", fontweight="bold")
        ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
        ax.grid(axis="y", color="#E4E9F0", linewidth=0.8); ax.set_axisbelow(True)
    axes[0].set_ylabel("Share of snippets with gold CWE in top-k")
    axes[0].legend(frameon=False, fontsize=7.5, loc="lower left")
    fig.tight_layout()
    fig.savefig(os.path.join(_RESULTS, "retrieval_comparison.png"))


if __name__ == "__main__":
    run()
