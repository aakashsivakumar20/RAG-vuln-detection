"""How informative is the retrieval margin (top-1 minus top-2 fused score) as a confidence signal?

The severity scorer's fallback path (no LLM verdict) downgrades a candidate when the margin is below
MARGIN_CONFIDENCE_THRESHOLD. The threshold was set from the DEVELOPMENT set only; the held-out numbers
below are reported, not tuned. Writes results/margin_calibration.json.
"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from retrieval_eval import HybridRetriever, load_knowledge_base, load_set, record_id
from rag_vuln_detect.severity.scorer import MARGIN_CONFIDENCE_THRESHOLD as T

kb, idf = load_knowledge_base()
r = HybridRetriever(kb, idf)
out = {"threshold": T, "sets": {}}
for name in ("dev", "heldout"):
    right, wrong = [], []
    for s in load_set(name):
        h = r.search(s["code"], top_k=2, language=s.get("language"))
        (right if record_id(h[0]) == s["expected_cwe"] else wrong).append(h[0]["similarity"] - h[1]["similarity"])
    hi_r, hi_w = sum(m >= T for m in right), sum(m >= T for m in wrong)
    mean = lambda x: round(sum(x) / len(x), 4) if x else None
    out["sets"][name] = {"n": len(right) + len(wrong), "top1_correct": len(right), "top1_wrong": len(wrong),
                         "mean_margin_correct": mean(right), "mean_margin_wrong": mean(wrong),
                         "confident_correct": hi_r, "confident_wrong": hi_w,
                         "precision_when_confident": round(hi_r / (hi_r + hi_w), 4) if hi_r + hi_w else None,
                         "wrong_flagged_low_confidence": len(wrong) - hi_w,
                         "correct_flagged_low_confidence": len(right) - hi_r}
p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results", "margin_calibration.json")
json.dump(out, open(p, "w"), indent=2)
print(json.dumps(out, indent=2))
