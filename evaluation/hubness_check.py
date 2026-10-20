"""
Label-free sanity check for the knowledge base: run the retriever over UNLABELLED code (this project's own source
and the dashboard) and count which KB entries are returned most often. An entry that dominates the top-1/top-6
lists for unrelated code ("hub") has indicator text that is too generic; fixing hubs needs no ground-truth labels,
so it does not touch the held-out benchmark.

    python evaluation/hubness_check.py
"""
import collections
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from rag_vuln_detect.chunking.chunker import chunk_file  # noqa: E402
from rag_vuln_detect.knowledge_base.build_kb import load_kb_records, load_knowledge_base  # noqa: E402
from rag_vuln_detect.retrieval.hybrid import HybridRetriever, record_id  # noqa: E402


def main(top_n: int = 12) -> None:
    root = os.path.join(HERE, "..")
    ix, idf = load_knowledge_base()
    retriever = HybridRetriever(ix, idf)
    files = [(f, "python") for f in glob.glob(os.path.join(root, "src/rag_vuln_detect/**/*.py"), recursive=True)]
    files += [(f, "python") for f in glob.glob(os.path.join(root, "evaluation/*.py"))]
    files += [(f, "javascript") for f in glob.glob(os.path.join(root, "dashboard/src/**/*.js*"), recursive=True)]
    chunks = []
    for f, lang in files:
        chunks += [c for c in chunk_file(f, os.path.relpath(f, root), lang) if len(c.text.splitlines()) >= 3]
    top1, top6 = collections.Counter(), collections.Counter()
    for c in chunks:
        hits = retriever.search(c.text, top_k=6, language=c.language)
        top1[record_id(hits[0])] += 1
        for h in hits:
            top6[record_id(h)] += 1
    names = {record_id(r): r["name"] for r in load_kb_records()}
    n_kb = len(names)
    print(f"{len(chunks)} unlabelled chunks, {n_kb} KB entries; distinct entries returned top-1: {len(top1)}, in top-6: {len(top6)}")
    print(f"if retrieval were uniform each entry would be top-1 for ~{len(chunks) / n_kb:.1f} chunks")
    for title, cnt in (("top-1", top1), ("in top-6", top6)):
        print(f"\nmost frequent {title}:")
        for k, v in cnt.most_common(top_n):
            print(f"  {k:<9}{v:>4}  {names.get(k, '')[:70]}")
    print("\nshare of top-1 taken by the 5 busiest entries: %.0f%%" % (100 * sum(v for _, v in top1.most_common(5)) / len(chunks)))


if __name__ == "__main__":
    main()
