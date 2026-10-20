"""Test helper: loads the evaluation scripts (which live outside the package) for the language-set regression test."""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EVAL = os.path.join(ROOT, "evaluation")
if EVAL not in sys.path:
    sys.path.insert(0, EVAL)


def load_langs():
    with open(os.path.join(EVAL, "langs_snippets.json")) as f:
        sn = json.load(f)["snippets"]
    with open(os.path.join(EVAL, "langs_patched.json")) as f:
        pt = json.load(f)["patched"]
    return sn, pt


def final_metrics(snippets):
    import retrieval_eval as ev
    kb_index, idf = ev.load_knowledge_base()
    fn = ev.hybrid_rank_fn(ev.HybridRetriever(kb_index, idf))
    return ev.metrics(ev.ranks_for(snippets, fn))
