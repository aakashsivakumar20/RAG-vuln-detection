"""
Automated tests for the Severity Scoring module (severity/scorer.py). Run with:
    cd src && python -m pytest tests/ -v
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rag_vuln_detect.severity.scorer import (
    score_finding,
    MARGIN_CONFIDENCE_THRESHOLD,
    BASE_SEVERITY,
    OWASP_CATEGORY_SEVERITY,
)


def _cwe_hit(cwe_id, owasp_category, similarity):
    return {
        "standard": "CWE",
        "cwe_id": cwe_id,
        "owasp_category": owasp_category,
        "similarity": similarity,
    }


def _owasp_hit(code, similarity):
    return {"standard": "OWASP", "code": code, "similarity": similarity}


def test_sql_injection_high_confidence_keeps_critical_band():
    top1 = _cwe_hit("CWE-89", "A05:2025", 0.93)
    top2 = _cwe_hit("CWE-78", "A05:2025", 0.85)
    result = score_finding(top1, top2)
    assert result.cwe_id == "CWE-89"
    assert result.base_band == "Critical"
    assert result.final_band == "Critical"
    assert result.low_confidence is False
    assert result.margin == 0.08


def test_low_margin_downgrades_band_and_flags_low_confidence():
    top1 = _cwe_hit("CWE-89", "A05:2025", 0.90)
    top2 = _cwe_hit("CWE-78", "A05:2025", 0.895)  # margin 0.005 < threshold
    result = score_finding(top1, top2)
    assert result.margin < MARGIN_CONFIDENCE_THRESHOLD
    assert result.low_confidence is True
    assert result.base_band == "Critical"
    assert result.final_band == "High"  # one step down from Critical
    assert result.final_score < result.base_score


def test_margin_exactly_at_threshold_is_not_low_confidence():
    top1 = _cwe_hit("CWE-79", "A05:2025", 0.90)
    top2 = _cwe_hit("CWE-78", "A05:2025", 0.90 - MARGIN_CONFIDENCE_THRESHOLD)
    result = score_finding(top1, top2)
    assert result.low_confidence is False
    assert result.final_band == result.base_band


def test_no_second_hit_treated_as_full_confidence():
    top1 = _cwe_hit("CWE-79", "A02:2025", 0.91)
    result = score_finding(top1, None)
    assert result.margin == 1.0
    assert result.low_confidence is False
    assert result.final_band == "Medium"


def test_owasp_only_hit_uses_category_fallback():
    top1 = _owasp_hit("A09:2025", 0.88)
    top2 = _owasp_hit("A02:2025", 0.70)
    result = score_finding(top1, top2)
    assert result.cwe_id is None
    assert result.owasp_category == "A09:2025"
    assert result.base_band == "Low"
    assert result.final_band == "Low"  # Low downgrades to Low (floor)


def test_low_band_downgrade_floors_at_low():
    top1 = _owasp_hit("A09:2025", 0.90)
    top2 = _owasp_hit("A02:2025", 0.895)  # margin below threshold
    result = score_finding(top1, top2)
    assert result.low_confidence is True
    assert result.base_band == "Low"
    assert result.final_band == "Low"


def test_unknown_weakness_falls_back_to_default_severity():
    top1 = {"standard": "CWE", "cwe_id": "CWE-9999", "owasp_category": None, "similarity": 0.9}
    result = score_finding(top1, None)
    assert result.base_band == "Medium"
    assert result.base_score == 5.0


def test_every_cwe_and_owasp_table_entry_has_valid_band():
    valid_bands = {"Low", "Medium", "High", "Critical"}
    for cwe_id, (band, score) in BASE_SEVERITY.items():
        assert band in valid_bands, f"{cwe_id} has invalid band {band}"
        assert 0.1 <= score <= 10.0, f"{cwe_id} score {score} out of CVSS range"
    for code, (band, score) in OWASP_CATEGORY_SEVERITY.items():
        assert band in valid_bands, f"{code} has invalid band {band}"
        assert 0.1 <= score <= 10.0, f"{code} score {score} out of CVSS range"


def test_rationale_mentions_margin_and_threshold():
    top1 = _cwe_hit("CWE-89", "A05:2025", 0.93)
    top2 = _cwe_hit("CWE-78", "A05:2025", 0.85)
    result = score_finding(top1, top2)
    assert "margin" in result.rationale
    assert str(MARGIN_CONFIDENCE_THRESHOLD) in result.rationale


def test_to_dict_round_trips_all_fields():
    top1 = _cwe_hit("CWE-89", "A05:2025", 0.93)
    result = score_finding(top1, None)
    d = result.to_dict()
    assert d["cwe_id"] == "CWE-89"
    assert d["final_band"] == "Critical"
    assert set(d.keys()) == {
        "cwe_id", "owasp_category", "base_band", "base_score", "margin",
        "low_confidence", "final_band", "final_score", "rationale",
    }
