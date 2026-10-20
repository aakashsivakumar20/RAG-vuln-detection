"""Release v2: scanning Java, Kotlin, PHP, Go, C#, Ruby, C/C++ and Rust (chunking, ingestion, sink rules, demo)."""
import json
import os
import sqlite3
import sys

import pytest

from rag_vuln_detect.chunking import chunker
from rag_vuln_detect.chunking.chunker import chunk_file, supported_languages
from rag_vuln_detect.ingestion.clone import LANGUAGE_BY_EXTENSION, ingest_repository
from rag_vuln_detect.retrieval import patterns

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EVAL = os.path.join(ROOT, "evaluation")

SAMPLES = {
    "java": ("A.java", "class A { A(){ int x = 1; } public void f(String s){ run(s); } }", ["A", "f"]),
    "php": ("a.php", "<?php\nfunction f($a){ echo $a; }\nclass B { public function g($x){ return $x; } }\n$y = $_GET['q'];\n$z = $y;\necho $z;", ["f", "g", "<top-level script>"]),
    "go": ("a.go", "package main\nfunc f(a string) {}\nfunc (s *S) g() {}", ["f", "g"]),
    "csharp": ("a.cs", "class A { string F(string s){ return s; } A(){} }", ["F", "A"]),
    "ruby": ("a.rb", "class A\n def f(x)\n  x\n end\n def self.g; end\nend", ["f", "g"]),
    "c": ("a.c", "int *f(char *a){ return 0; }\nstatic void g(void){}", ["f", "g"]),
    "cpp": ("a.cpp", "class A { void h(){} };\nint A::f(char *a){ return 0; }", ["h", "A::f"]),
    "rust": ("a.rs", "fn f(a: &str) {}\nimpl S { fn g(&self) {} }", ["f", "g"]),
    "kotlin": ("a.kt", "class A { fun f(x: String) { } }\nfun g() {}", ["f", "g"]),
}


def test_all_grammars_available():
    assert set(supported_languages()) >= {"python", "javascript", "typescript", *SAMPLES}


@pytest.mark.parametrize("lang", sorted(SAMPLES))
def test_chunker_splits_functions_and_names_them(tmp_path, lang):
    fname, src, names = SAMPLES[lang]
    p = tmp_path / fname
    p.write_text(src)
    chunks = chunk_file(str(p), fname, lang)
    assert [c.name for c in chunks] == names
    assert all(c.language == lang and c.start_line >= 1 and c.text.strip() for c in chunks)


def test_missing_grammar_degrades_to_line_windows(tmp_path, monkeypatch):
    monkeypatch.setitem(chunker._EXTRA_LANGUAGES, "go", ("tree_sitter_not_installed", "language", {"function_declaration"}))
    monkeypatch.delitem(chunker._PARSERS, "go", raising=False)
    p = tmp_path / "a.go"
    p.write_text("package main\nfunc f() {}\n")
    chunks = chunk_file(str(p), "a.go", "go")
    assert chunks and chunks[0].kind == "fallback_window"


def test_ingestion_recognises_every_new_extension(tmp_path):
    names = {"A.java": "java", "a.kt": "kotlin", "a.php": "php", "a.go": "go", "a.cs": "csharp", "a.rb": "ruby",
             "a.c": "c", "a.h": "c", "a.cpp": "cpp", "a.rs": "rust", "a.py": "python", "a.tsx": "typescript"}
    for n in names:
        (tmp_path / n).write_text("x\n")
    (tmp_path / "notes.txt").write_text("x\n")
    rep = ingest_repository(str(tmp_path), workdir=str(tmp_path / "_w"))
    got = {os.path.basename(f.rel_path): f.language for f in rep.files_kept}
    assert got == names and rep.files_skipped_unsupported_language == 1
    assert LANGUAGE_BY_EXTENSION[".cc"] == "cpp" and LANGUAGE_BY_EXTENSION[".kts"] == "kotlin"


def _hits(code, lang):
    return patterns.cwe_scores(patterns.scan(code, lang, patterns.load_rules()))


def test_rules_cover_every_new_language_and_respect_safe_code():
    cases = [
        ("java", 'st.executeQuery("SELECT * FROM t WHERE a = \'" + a + "\'");', "CWE-89"),
        ("java", 'Runtime.getRuntime().exec("ping " + host);', "CWE-78"),
        ("kotlin", 'conn.createStatement().executeQuery("SELECT * FROM t WHERE a = \'$a\'")', "CWE-89"),
        ("php", 'mysqli_query($c, "SELECT * FROM t WHERE id = " . $_GET["id"]);', "CWE-89"),
        ("php", 'echo shell_exec("ping " . $_POST["h"]);', "CWE-78"),
        ("go", 'exec.Command("sh", "-c", "ping "+host).Output()', "CWE-78"),
        ("go", 'tls.Config{InsecureSkipVerify: true}', "CWE-295"),
        ("csharp", 'new SqlCommand("SELECT * FROM T WHERE N = \'" + n + "\'", c);', "CWE-89"),
        ("csharp", 'var f = new BinaryFormatter();', "CWE-502"),
        ("ruby", 'User.where("name = \'#{params[:n]}\'")', "CWE-89"),
        ("ruby", 'YAML.load(params[:p])', "CWE-502"),
        ("c", 'char b[8]; strcpy(b, input);', "CWE-120"),
        ("c", 'void f(char *m) { syslog(LOG_INFO, m); }', "CWE-134"),
        ("cpp", 'system(cmd);', "CWE-78"),
        ("rust", 'Command::new("sh").arg("-c").arg(format!("ping {}", h))', "CWE-78"),
        ("rust", 'reqwest::Client::builder().danger_accept_invalid_certs(true)', "CWE-295"),
    ]
    for lang, code, cwe in cases:
        assert _hits(code, lang).get(cwe, 0) >= 0.5, (lang, cwe)
    # safe variants must not fire the same CWE strongly
    assert _hits('conn.prepareStatement("SELECT * FROM t WHERE a = ?");', "java").get("CWE-89", 0) < 0.5
    assert _hits('echo htmlspecialchars($_GET["q"]);', "php").get("CWE-79", 0) < 0.5
    assert _hits('exec.Command("ping", "-c", "1", host).Output()', "go").get("CWE-78", 0) < 0.5
    assert _hits('syslog(LOG_INFO, "%s", m);', "c").get("CWE-134", 0) < 0.5
    # language filter: a Java-only rule must not fire on Python code
    assert _hits('Runtime.getRuntime().exec("ping " + host);', "python").get("CWE-78", 0) < 0.5


def test_language_set_files_are_consistent_and_retrieval_stays_accurate():
    from retrieval_eval_shim import load_langs, final_metrics
    sn, patched = load_langs()
    assert len(sn) == len(patched) == 67
    assert {s["language"] for s in sn} == {"java", "php", "go", "csharp", "ruby", "c", "rust", "kotlin"}
    assert all(patched[s["id"]].strip() != s["code"].strip() for s in sn)
    m = final_metrics(sn)
    # regression guard (measured 86.6% / 100% when written); generous margins so it only trips on real breakage
    assert m["top1"] >= 0.75 and m["top3"] >= 0.92


def test_multilang_demo_scan_finds_something_in_every_language(tmp_path):
    from rag_vuln_detect.llm.analyzer import SecurityAnalyzer
    from rag_vuln_detect.pipeline.scan import ScanConfig, run_scan
    db = str(tmp_path / "ml.db")
    res = run_scan(os.path.join(ROOT, "demo", "multilang_demo_app"), ScanConfig(max_candidates_no_llm=60),
                   analyzer=SecurityAnalyzer(None, mode="live"), db_path=db)
    assert res["counts"]["files_analysable"] == 8
    rows = sqlite3.connect(db).execute("select file_path from findings").fetchall()
    dirs = {r[0].split("/")[0] for r in rows}
    assert dirs == {"java", "php", "go", "csharp", "ruby", "c", "rust", "kotlin"}


def test_minified_and_bundled_js_is_skipped(tmp_path):
    (tmp_path / "app.js").write_text("function f(a) {\n  return a + 1;\n}\n" * 3)
    (tmp_path / "lib-min.js").write_text("function f(a){return a+1}\n")
    (tmp_path / "one_line.js").write_text("var a=1;" * 2000)
    rep = ingest_repository(str(tmp_path), workdir=str(tmp_path / "_w"))
    assert [os.path.basename(f.rel_path) for f in rep.files_kept] == ["app.js"]
