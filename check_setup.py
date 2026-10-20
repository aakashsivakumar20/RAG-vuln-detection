"""Quick self-check of this installation:  python check_setup.py [--llm]

Verifies Python, the packages, the bundled GloVe vectors and knowledge base, runs a tiny scan of the
bundled demo app WITHOUT any LLM, and (with --llm) sends one small request to your configured
free-tier provider to confirm the key works.
"""
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "src"))
ok_all = True


def check(name, fn):
    global ok_all
    try:
        detail = fn()
        print(f"  [ OK ] {name}" + (f" - {detail}" if detail else ""))
    except Exception as e:  # noqa: BLE001
        ok_all = False
        print(f"  [FAIL] {name} - {type(e).__name__}: {e}")


def main():
    print(f"Python {sys.version.split()[0]} ({sys.platform})")
    if not (3, 10) <= sys.version_info[:2] <= (3, 14):
        print("  [WARN] tested on Python 3.10-3.14")
    print("Packages")
    for mod, label in (("numpy", "numpy"), ("faiss", "faiss-cpu"), ("tree_sitter", "tree-sitter"),
                       ("tree_sitter_python", "tree-sitter-python"), ("tree_sitter_javascript", "tree-sitter-javascript"),
                       ("tree_sitter_typescript", "tree-sitter-typescript")):
        check(label, lambda m=mod: __import__(m).__name__ and "")
    from rag_vuln_detect.chunking.chunker import supported_languages
    langs = supported_languages()
    check("language grammars (Java, PHP, Go, C#, Ruby, C/C++, Rust, Kotlin)",
          lambda: f"{len(langs)} languages with syntax-aware chunking: {', '.join(langs)}" if len(langs) == 12
          else (_ for _ in ()).throw(RuntimeError("missing grammar(s) - run: pip install -r requirements.txt; present: " + ", ".join(langs))))
    print("Project data")
    from rag_vuln_detect.embeddings.glove import load_glove
    check("GloVe vectors (bundled)", lambda: f"{len(load_glove()):,} words")
    from rag_vuln_detect.knowledge_base.build_kb import load_knowledge_base
    check("Security knowledge base", lambda: f"{len(load_knowledge_base()[0])} entries")
    check("Dashboard build", lambda: "found" if os.path.isdir(os.path.join(ROOT, "dashboard", "dist")) else (_ for _ in ()).throw(FileNotFoundError("dashboard/dist missing")))

    print("Pipeline (no LLM)")
    def tiny_scan():
        import tempfile
        from rag_vuln_detect.llm.analyzer import SecurityAnalyzer
        from rag_vuln_detect.pipeline.scan import ScanConfig, run_scan
        db = os.path.join(tempfile.mkdtemp(), "check.db")
        res = run_scan(os.path.join(ROOT, "demo", "vulnerable_demo_app"), ScanConfig(max_candidates_no_llm=5),
                       analyzer=SecurityAnalyzer(None, mode="live"), db_path=db)
        return f"{res['counts']['chunks_total']} code units parsed, {res['counts']['unverified']} candidates in {res['timings']['total_s']}s"
    check("end-to-end scan of the demo app", tiny_scan)

    print("LLM")
    from rag_vuln_detect.llm.providers import make_provider
    p = make_provider()
    if p is None:
        print("  [ -- ] no key configured (copy .env.example to .env, or paste a key in the dashboard Settings). "
              "Scans will list UNVERIFIED candidates only.")
    else:
        print(f"  [ OK ] provider configured: {p.name}")
        if "--llm" in sys.argv:
            ping = 'Reply with the JSON object {"ok": true}'
            check("test request", lambda: "model %s replied %r" % (p.model, p.complete(ping, "ping", 30)[:40]))
        else:
            print("         (run with --llm to send a test request)")
    print("\nAll checks passed." if ok_all else "\nSome checks FAILED - see above.")
    return 0 if ok_all else 1


if __name__ == "__main__":
    raise SystemExit(main())
