"""
Fit the hybrid-retrieval fusion weight (alpha) on the DEV set ONLY.

The held-out set is deliberately never loaded here, so the reported held-out
numbers (evaluation/run_retrieval_report.py) are an honest generalisation
estimate. Prints the grid and the chosen alpha; the chosen value is then
written into src/rag_vuln_detect/retrieval/hybrid.py as DEFAULT_ALPHA.
"""
from retrieval_eval import *  # noqa

if __name__ == "__main__":
    kb_index, idf = load_knowledge_base()
    dev = load_set("dev")
    print("DEV set only (n=%d)\n" % len(dev))
    print("dense (plain)  :", fmt(metrics(ranks_for(dev, dense_rank_fn(kb_index, idf, False)))))
    print("dense (IDF)    :", fmt(metrics(ranks_for(dev, dense_rank_fn(kb_index, idf, True)))))
    grid = []
    for use_signals in (False, True):
        r = HybridRetriever(kb_index, idf, use_signals=use_signals, use_rules=False, prior=0.0)
        print(f"\nhybrid, signals={'on' if use_signals else 'off'}, rules off")
        for a in (0.0, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 1.0):
            m = metrics(ranks_for(dev, hybrid_rank_fn(r, a, 0.0)))
            print(f"  alpha={a:.1f}  {fmt(m)}")
            if use_signals:
                grid.append((a, m))
    # Selection rule (fixed before looking at any held-out number): with only 22 dev snippets one snippet is
    # 4.5 points of top-1, which is noise. Take every alpha whose dev top-1 is within ONE snippet of the best,
    # and among those prefer the one closest to 0.5, so the dense half is not discarded on a one-snippet difference.
    best_top1 = max(m["top1"] for _, m in grid)
    tol = 1.0 / len(dev) + 1e-9
    cands = [(a, m) for a, m in grid if m["top1"] >= best_top1 - tol]
    chosen = min(cands, key=lambda am: (abs(am[0] - 0.5), -am[1]["mrr"]))[0]
    print(f"\nbest dev top-1 = {best_top1:.1%}; alphas within one snippet: {[a for a, _ in cands]}")
    print("chosen alpha (closest to 0.5 among those):", chosen)

    # Static-rule weight (beta), with alpha fixed at the value chosen above. Same rule: the smallest beta whose dev
    # top-1 is within one snippet of the best (a larger weight than needed just lets rules override everything).
    print("\nsink rules on, alpha=%.1f" % chosen)
    r = HybridRetriever(kb_index, idf, use_signals=True, use_rules=True, prior=0.0)
    bgrid = []
    for b in (0.0, 0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0):
        m = metrics(ranks_for(dev, hybrid_rank_fn(r, chosen, b)))
        print(f"  beta={b:.2f}  {fmt(m)}")
        bgrid.append((b, m))
    bbest = max(m["top1"] for _, m in bgrid)
    bcands = [(b, m) for b, m in bgrid if m["top1"] >= bbest - tol]
    print("chosen beta (smallest within one snippet of the best):", min(bcands, key=lambda bm: bm[0])[0])
