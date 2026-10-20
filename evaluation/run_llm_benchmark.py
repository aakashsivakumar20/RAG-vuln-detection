"""
LLM verdict benchmark: does retrieval-augmented context help the LLM?

Uses the 161 labelled vulnerable snippets (22 development + 38 held-out + 40 extended-CWE + 61 second held-out) and, for every one,
a PATCHED counterpart that fixes the weakness (evaluation/benchmark_patched.json, extended_patched.json). Each snippet
is judged independently, in three configurations:

  retrieval-only  no LLM: every snippet is flagged with the retriever's top-1 CWE
                  (shows why a verdict step is needed: it cannot tell patched from vulnerable)
  llm-only        the LLM sees only the code
  llm+rag         the LLM also sees the top-6 retrieved OWASP/CWE entries and CWE rubrics

Metrics (patched/vulnerable pairs, PairVul-style):
  vuln_recall           vulnerable snippets flagged vulnerable
  false_positive_rate   patched snippets flagged vulnerable
  accuracy              correct judgements over all snippets
  pair_accuracy         pairs where the vulnerable version is flagged AND the patched version is not
  cwe_accuracy          flagged vulnerable snippets given the labelled CWE (exact match)
Wilson 95% intervals are reported for pair accuracy; a paired comparison counts the pairs on
which llm+rag and llm-only differ.

Needs a free-tier key (GROQ_API_KEY or GEMINI_API_KEY in .env). Verdicts are cached
(data/llm_cache.jsonl), so an interrupted run resumes where it stopped and a finished run can be
re-printed offline with --mode replay.

    python evaluation/run_llm_benchmark.py                 # all 161 pairs, both LLM configurations
    python evaluation/run_llm_benchmark.py --limit 10      # quick trial
    python evaluation/run_llm_benchmark.py --mode replay   # re-score from cache, no network
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from rag_vuln_detect.knowledge_base.build_kb import load_knowledge_base  # noqa: E402
from rag_vuln_detect.llm.analyzer import SecurityAnalyzer  # noqa: E402
from rag_vuln_detect.llm.pool import DaemonPool  # noqa: E402
from rag_vuln_detect.llm.providers import make_provider  # noqa: E402
from rag_vuln_detect.retrieval.hybrid import HybridRetriever, record_id  # noqa: E402

_HERE = os.path.dirname(os.path.abspath(__file__))
_RESULTS = os.path.join(_HERE, "..", "results")


ALL_SPLITS = ("dev", "heldout", "extended", "heldout2")
OPTIONAL_SPLITS = ("langs",)          # v2 language set (Java, PHP, Go, C#, Ruby, C, Rust, Kotlin): add with --splits ...,langs


def load_pairs(limit: int | None = None, splits: tuple = ALL_SPLITS) -> list[dict]:
    with open(os.path.join(_HERE, "benchmark_snippets.json")) as f:
        dev = json.load(f)["snippets"]
    with open(os.path.join(_HERE, "heldout_snippets.json")) as f:
        held = json.load(f)["snippets"]
    with open(os.path.join(_HERE, "extended_snippets.json")) as f:
        ext = json.load(f)["snippets"]
    with open(os.path.join(_HERE, "heldout2_snippets.json")) as f:
        h2 = json.load(f)["snippets"]
    with open(os.path.join(_HERE, "benchmark_patched.json")) as f:
        patched = json.load(f)["patched"]
    with open(os.path.join(_HERE, "extended_patched.json")) as f:
        patched.update(json.load(f)["patched"])
    with open(os.path.join(_HERE, "heldout2_patched.json")) as f:
        patched.update(json.load(f)["patched"])
    with open(os.path.join(_HERE, "langs_snippets.json")) as f:
        langs = json.load(f)["snippets"]
    with open(os.path.join(_HERE, "langs_patched.json")) as f:
        patched.update(json.load(f)["patched"])
    pairs = []
    for split, items in (("dev", dev), ("heldout", held), ("extended", ext), ("heldout2", h2), ("langs", langs)):
        if split not in splits:
            continue
        for s in items:
            pairs.append({"id": s["id"], "split": split, "language": s.get("language", "python"),
                          "cwe": s["expected_cwe"], "vulnerable": s["code"], "patched": patched[s["id"]]})
    if limit:
        # take a spread across both splits rather than only the first CWEs
        step = max(1, len(pairs) // limit)
        pairs = pairs[::step][:limit]
    return pairs


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - m) / d, (c + m) / d)


def judge(analyzer, retriever, code, language, use_rag):
    hits = retriever.search(code, top_k=6, language=language)
    return analyzer.analyze(code, file_path=f"snippet.{ 'py' if language == 'python' else 'js'}", language=language,
                            kb_hits=hits, repo_context=None, use_rag=use_rag), hits


def score(rows: list[dict]) -> dict:
    ok = [r for r in rows if r["v_ok"] and r["p_ok"]]          # pairs with both verdicts available
    n = len(ok)
    if n == 0:
        return {"n_pairs": 0}
    tp = sum(r["v_flag"] for r in ok)
    fp = sum(r["p_flag"] for r in ok)
    cwe = sum(1 for r in ok if r["v_flag"] and r["v_cwe"] == r["cwe"])
    pair = sum(1 for r in ok if r["v_flag"] and not r["p_flag"])
    lo, hi = wilson(pair, n)
    return {"n_pairs": n, "vuln_recall": tp / n, "false_positive_rate": fp / n,
            "accuracy": (tp + (n - fp)) / (2 * n), "pair_accuracy": pair / n,
            "pair_accuracy_ci95": [round(lo, 4), round(hi, 4)],
            "cwe_accuracy": cwe / n, "cwe_accuracy_of_flagged": (cwe / tp) if tp else None}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--limit", type=int, default=None, help="number of pairs to use (default: all 161)")
    ap.add_argument("--mode", default="auto", choices=["auto", "live", "replay"])
    ap.add_argument("--splits", default=",".join(ALL_SPLITS), help="comma list of dev,heldout,extended,heldout2,langs (default: the 161 Python/JS pairs; add langs for the 67 other-language pairs)")
    ap.add_argument("--configs", default="llm-only,llm+rag")
    ap.add_argument("--workers", type=int, default=4, help="concurrent LLM requests (default 4)")
    ap.add_argument("--out-dir", default=_RESULTS, help="where to write llm_benchmark.json / .csv")
    args = ap.parse_args()

    provider = None if args.mode == "replay" else make_provider()
    analyzer = SecurityAnalyzer(provider, mode=args.mode)
    if not analyzer.available:
        print("No LLM configured. Put GROQ_API_KEY (console.groq.com/keys) or GEMINI_API_KEY "
              "(aistudio.google.com/apikey) in a .env file in the project root, then re-run.")
        return 2
    print("LLM:", analyzer.describe())
    kb_index, idf = load_knowledge_base()
    retriever = HybridRetriever(kb_index, idf)
    pairs = load_pairs(args.limit, tuple(x.strip() for x in args.splits.split(",") if x.strip()))
    configs = [c.strip() for c in args.configs.split(",") if c.strip()]
    print(f"{len(pairs)} pairs x {len(configs)} configurations = {len(pairs) * 2 * len(configs)} LLM judgements "
          "(cached ones are free; free tiers allow roughly 10-30 requests/min)")

    per_item: dict[str, list[dict]] = {c: [] for c in configs}
    t0 = time.time()
    first_error = ""

    def run_pair(cfg: str, p: dict) -> dict:
        row = {"id": p["id"], "split": p["split"], "cwe": p["cwe"]}
        for role in ("vulnerable", "patched"):
            v, hits = judge(analyzer, retriever, p[role], p["language"], cfg == "llm+rag")
            tag = "v" if role == "vulnerable" else "p"
            row[f"{tag}_ok"] = v.status == "ok"
            row[f"{tag}_flag"] = bool(v.vulnerable) if v.status == "ok" else None
            row[f"{tag}_cwe"] = v.cwe_id
            row[f"{tag}_conf"] = v.confidence
            row[f"{tag}_error"] = "" if v.status == "ok" else f"{v.status}: {v.error}"
            if tag == "v":
                row["retrieval_top1"] = record_id(hits[0])
        return row

    # a few requests in flight at once hide network latency; the provider's rate limiter still caps requests/minute
    pool = DaemonPool(args.workers, name="bench")
    try:
        for cfg in configs:
            futs = [pool.submit(run_pair, cfg, p) for p in pairs]
            for i, fut in enumerate(futs, 1):
                row = fut.result()
                per_item[cfg].append(row)
                first_error = first_error or row["v_error"] or row["p_error"]
                if i % 5 == 0 or i == len(pairs):
                    s = analyzer.stats
                    print(f"  [{cfg}] {i}/{len(pairs)} pairs   calls={s['calls']} cache={s['cache_hits']} errors={s['errors']}", flush=True)
                if analyzer.stats["errors"] >= 8 and analyzer.stats["calls"] == analyzer.stats["errors"]:
                    print("Stopping: the provider keeps failing.", first_error)
                    return 3
    finally:
        pool.shutdown()

    results: dict = {}
    by_split: dict = {}
    for cfg in configs:
        results[cfg] = score(per_item[cfg])
        by_split[cfg] = {sp: score([r for r in per_item[cfg] if r["split"] == sp])
                         for sp in ALL_SPLITS + OPTIONAL_SPLITS}
    # retrieval-only baseline: flags everything with its top-1 CWE
    base_rows = per_item[configs[0]]
    n = len(base_rows)
    results["retrieval-only (no verdict step)"] = {
        "n_pairs": n, "vuln_recall": 1.0, "false_positive_rate": 1.0, "accuracy": 0.5, "pair_accuracy": 0.0,
        "pair_accuracy_ci95": [round(wilson(0, n)[0], 4), round(wilson(0, n)[1], 4)],
        "cwe_accuracy": sum(1 for r in base_rows if r["retrieval_top1"] == r["cwe"]) / n if n else 0,
        "cwe_accuracy_of_flagged": sum(1 for r in base_rows if r["retrieval_top1"] == r["cwe"]) / n if n else 0}

    paired = None
    if "llm-only" in per_item and "llm+rag" in per_item:
        a = {r["id"]: r for r in per_item["llm-only"] if r["v_ok"] and r["p_ok"]}
        b = {r["id"]: r for r in per_item["llm+rag"] if r["v_ok"] and r["p_ok"]}
        both = a.keys() & b.keys()
        ok = lambda r: r["v_flag"] and not r["p_flag"]
        paired = {"pairs_compared": len(both),
                  "rag_correct_llm_only_wrong": sum(1 for k in both if ok(b[k]) and not ok(a[k])),
                  "llm_only_correct_rag_wrong": sum(1 for k in both if ok(a[k]) and not ok(b[k])),
                  "both_correct": sum(1 for k in both if ok(a[k]) and ok(b[k])),
                  "both_wrong": sum(1 for k in both if not ok(a[k]) and not ok(b[k]))}

    try:
        model = analyzer.provider.model if analyzer.provider else "cached"
    except Exception:  # noqa: BLE001
        model = "unknown"
    out = {"generated_at": time.strftime("%Y-%m-%d %H:%M"), "provider": analyzer.provider.name if analyzer.provider else "cache",
           "model": model, "n_pairs": len(pairs), "configs": results, "by_split": by_split, "paired_comparison": paired,
           "stats": analyzer.stats, "seconds": round(time.time() - t0, 1),
           "notes": ("Single run at temperature 0 on one model; 161 pairs gives wide confidence intervals "
                     "(see pair_accuracy_ci95), so differences of a few points are not significant. "
                     "The snippets and patched counterparts are project-authored, not taken from a public benchmark.")}
    os.makedirs(args.out_dir, exist_ok=True)
    with open(os.path.join(args.out_dir, "llm_benchmark.json"), "w") as f:
        json.dump(out, f, indent=2)
    with open(os.path.join(args.out_dir, "llm_benchmark_items.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["config", "id", "split", "expected_cwe", "retrieval_top1", "vuln_flagged", "vuln_cwe", "vuln_conf",
                    "patched_flagged", "patched_conf"])
        for cfg, rows in per_item.items():
            for r in rows:
                w.writerow([cfg, r["id"], r["split"], r["cwe"], r["retrieval_top1"], r["v_flag"], r["v_cwe"], r["v_conf"],
                            r["p_flag"], r["p_conf"]])

    print(f"\nModel: {out['provider']}/{out['model']}   pairs: {len(pairs)}")
    print(f"{'configuration':<34}{'pair acc':>10}{'recall':>9}{'FP rate':>9}{'CWE ok':>9}   95% CI (pair acc)")
    for name, m in results.items():
        if m.get("n_pairs"):
            ci = m["pair_accuracy_ci95"]
            print(f"{name:<34}{m['pair_accuracy']:>10.1%}{m['vuln_recall']:>9.1%}{m['false_positive_rate']:>9.1%}{m['cwe_accuracy']:>9.1%}   [{ci[0]:.1%}, {ci[1]:.1%}]")
    for cfg in configs:
        parts = [f"{sp}: {m['pair_accuracy']:.0%} (n={m['n_pairs']})" for sp, m in by_split[cfg].items() if m.get("n_pairs")]
        print(f"  pair accuracy by split, {cfg}: " + ", ".join(parts))
    if paired:
        print("Paired:", paired)
    if analyzer.stats["errors"]:
        print(f"WARNING: {analyzer.stats['errors']} request(s) failed (first: {first_error}); affected pairs were excluded.")
    print("Saved results/llm_benchmark.json and results/llm_benchmark_items.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
