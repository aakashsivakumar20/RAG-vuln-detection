"""
Automated tests for the Remediation Generation module
(remediation/generator.py, the template-based substitute for LLM-generated
remediation -- see module docstring). Run with:
    cd src && python -m pytest tests/ -v
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rag_vuln_detect.remediation.generator import (
    generate_remediation,
    coverage_summary,
    NO_TEMPLATE_AVAILABLE,
)


def test_sql_injection_has_parameterised_query_template():
    rem = generate_remediation("CWE-89")
    assert rem is not None
    assert rem.cwe_id == "CWE-89"
    assert "%s" in rem.after
    assert "+ name" in rem.before


def test_command_injection_template_avoids_shell_string():
    rem = generate_remediation("CWE-78")
    assert rem is not None
    assert "shell=False" in rem.after


def test_path_traversal_template_checks_commonpath():
    rem = generate_remediation("CWE-22")
    assert rem is not None
    assert "commonpath" in rem.after


def test_unknown_cwe_returns_none():
    assert generate_remediation("CWE-99999") is None


def test_none_cwe_returns_none():
    assert generate_remediation(None) is None


def test_documented_no_template_categories_return_none():
    for cwe_id in NO_TEMPLATE_AVAILABLE:
        assert generate_remediation(cwe_id) is None


def test_every_remediation_has_nonempty_before_after_and_explanation():
    for cwe_id in ["CWE-89", "CWE-78", "CWE-22", "CWE-502", "CWE-79", "CWE-94", "CWE-434"]:
        rem = generate_remediation(cwe_id)
        assert rem is not None, f"expected a template for {cwe_id}"
        assert rem.before.strip()
        assert rem.after.strip()
        assert rem.explanation.strip()
        assert rem.before != rem.after


def test_coverage_summary_counts_match_table():
    summary = coverage_summary()
    assert summary["templated_count"] >= 55 and summary["base_patterns"] >= 35
    assert summary["no_template_count"] == len(NO_TEMPLATE_AVAILABLE)
    assert not set(summary["templated_cwe_ids"]) & NO_TEMPLATE_AVAILABLE
    assert "CWE-89" in summary["templated_cwe_ids"]


# ------------------------------------------------ catalogue: per-language examples, steps, aliases

from rag_vuln_detect.remediation.fix_catalog import ALIASES, CATALOG  # noqa: E402


def test_every_catalogue_entry_is_complete():
    for cwe, e in CATALOG.items():
        assert cwe.startswith("CWE-") and e["title"] and len(e["explanation"]) > 40, cwe
        assert len(e["steps"]) >= 2 and e["reference"], cwe
        assert "py" in e["variants"] or "js" in e["variants"] or "c" in e["variants"], cwe
        for tag, (b, a) in e["variants"].items():
            assert b.strip() and a.strip() and b != a, (cwe, tag)
            assert tag in {"py", "js", "java", "php", "go", "cs", "rb", "c", "rs", "kt"}, (cwe, tag)
    assert all(v in CATALOG for v in ALIASES.values())


def test_language_specific_example_is_returned():
    java = generate_remediation("CWE-89", "java")
    assert java.language == "java" and "PreparedStatement" in java.after
    go = generate_remediation("CWE-78", "go")
    assert go.language == "go" and "exec.Command" in go.after
    assert generate_remediation("CWE-79", "csharp").language == "cs"
    assert generate_remediation("CWE-89", "typescript").language == "js"


def test_missing_language_falls_back_to_python_and_lists_available_languages():
    r = generate_remediation("CWE-1333", "rust")
    assert r.language == "py" and "py" in r.languages and "rs" not in r.languages


def test_aliases_resolve_but_keep_the_requested_cwe_id():
    r = generate_remediation("CWE-338")
    assert r.cwe_id == "CWE-338" and "secrets" in r.after
    assert generate_remediation("CWE-863").title == generate_remediation("CWE-862").title


def test_c_memory_templates_exist_for_the_common_overflow_ids():
    for cwe in ("CWE-120", "CWE-121", "CWE-122", "CWE-787", "CWE-134", "CWE-416", "CWE-476"):
        assert generate_remediation(cwe, "c") is not None


def test_templates_cover_most_cwes_the_rules_can_emit():
    import re
    from rag_vuln_detect.remediation.generator import has_template
    from rag_vuln_detect.retrieval import patterns
    cwes = {r.cwe for r in patterns.load_rules()}
    missing = sorted(c for c in cwes if not has_template(c))
    assert len(missing) <= 8, missing
