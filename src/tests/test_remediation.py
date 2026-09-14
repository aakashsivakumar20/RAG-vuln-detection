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
    assert summary["templated_count"] == 7
    assert summary["no_template_count"] == len(NO_TEMPLATE_AVAILABLE)
    assert summary["total_cwe_categories"] == 25
    assert "CWE-89" in summary["templated_cwe_ids"]
