"""
Severity Scoring module (per docs/chapter3_methodology.md, §3.3).

Rule-based, CVSS-inspired severity scoring, deliberately NOT dependent on an
LLM verdict -- this matches the design principle recorded in Chapter 3 and
session-log/SESSION_LOG.md: "Severity scoring is rule-based / CVSS-inspired,
not purely LLM-judged."

Two independent, auditable signals combine to score a *candidate* finding
(a code chunk paired with its nearest-matching Security Knowledge Base
entry via retrieval -- see the "candidate, not verified" note below):

1. A per-CWE / per-OWASP-category reference base score and band
   (BASE_SEVERITY / OWASP_CATEGORY_SEVERITY below), reflecting the severity
   commonly associated with each weakness category. This is this project's
   own deterministic lookup table, not a per-instance CVSS vector
   calculation -- a real CVSS score is computed per concrete vulnerability
   instance (attack vector, privileges required, impact, etc.), which this
   prototype cannot determine without the LLM Security Analysis stage
   (Chapter 3 §3.3, Review 4 scope). Using a per-category reference band is
   a documented simplification appropriate for a rule-based, explainable
   scorer, consistent with how many real-world tools present an initial
   "typical severity for this weakness class" before deeper triage.

2. A retrieval-confidence adjustment, using the *margin* between the top-1
   and top-2 Security Knowledge Base search similarity scores as a proxy
   for how confidently the retrieval step distinguished this weakness
   category from the next-closest one.

   Why margin, and not the raw top-1 similarity score: the raw cosine
   similarity produced by the GloVe/IDF embedding backbone
   (embeddings/embedder.py) clusters tightly in a high range (~0.85-0.95)
   regardless of whether the match is actually correct -- an artifact of
   averaged word-vector embeddings compressing most text into a similar
   region of the vector space. An absolute-score cutoff was tried against
   the labeled benchmark and found uninformative for that reason. The
   top1-vs-top2 MARGIN instead showed a real, measurable separation:
   recomputed directly against evaluation/benchmark_snippets.json, the
   mean margin was 0.0424 for snippets where the top-1 KB match was
   CORRECT, versus 0.0094 where it was WRONG. MARGIN_CONFIDENCE_THRESHOLD
   (0.015) is set near the midpoint of those two means. A margin below the
   threshold downgrades the severity band by one step and sets
   low_confidence=True, flagging the finding for manual/LLM review
   (Review 4 scope) rather than silently asserting a severity band the
   retrieval step was not confident about.

IMPORTANT -- candidate findings, not verified vulnerabilities:
This module scores the retrieval step's *candidate* match for a code
chunk. It cannot, on its own, confirm that the code chunk is actually
vulnerable -- that confirmation is the job of the LLM Security Analysis
module (Chapter 3 §3.3), which is Review 4 scope and not yet implemented.
Every severity produced here should be read as "IF this candidate match is
a true positive, THEN this is its estimated severity" -- the same way a
real SAST tool's raw output is a list of candidates for triage, not a list
of confirmed vulnerabilities. See pipeline/full_scan.py and
docs/chapter4_implementation.md §4.8 for how this is surfaced.
"""

from __future__ import annotations

import dataclasses

MARGIN_CONFIDENCE_THRESHOLD = 0.015

# Reference severity bands per CWE (see module docstring point 1). Chosen to
# reflect commonly-observed NVD/CVSS base-score ranges for each weakness
# category; band thresholds follow the standard CVSS v3.1 convention
# (0.1-3.9 Low, 4.0-6.9 Medium, 7.0-8.9 High, 9.0-10.0 Critical).
BASE_SEVERITY: dict[str, tuple[str, float]] = {
    "CWE-79": ("Medium", 6.1),
    "CWE-89": ("Critical", 9.8),
    "CWE-352": ("Medium", 6.5),
    "CWE-862": ("High", 7.5),
    "CWE-787": ("Critical", 9.1),
    "CWE-22": ("High", 7.5),
    "CWE-416": ("High", 8.1),
    "CWE-125": ("Medium", 6.5),
    "CWE-78": ("Critical", 9.8),
    "CWE-94": ("Critical", 9.8),
    "CWE-120": ("Critical", 9.1),
    "CWE-434": ("High", 8.1),
    "CWE-476": ("Medium", 5.5),
    "CWE-121": ("Critical", 9.1),
    "CWE-502": ("Critical", 9.8),
    "CWE-122": ("Critical", 9.1),
    "CWE-863": ("High", 7.5),
    "CWE-20": ("Medium", 6.5),
    "CWE-284": ("High", 7.5),
    "CWE-200": ("Medium", 5.3),
    "CWE-306": ("Critical", 9.1),
    "CWE-918": ("High", 7.5),
    "CWE-77": ("Critical", 9.8),
    "CWE-639": ("High", 7.1),
    "CWE-770": ("Medium", 5.3),
}

# Category-level fallback, used when the nearest KB match is an OWASP Top
# 10:2025 category entry rather than a specific CWE (the KB indexes both --
# see knowledge_base/build_kb.py).
OWASP_CATEGORY_SEVERITY: dict[str, tuple[str, float]] = {
    "A01:2025": ("High", 7.5),      # Broken Access Control
    "A02:2025": ("Medium", 6.5),    # Security Misconfiguration
    "A03:2025": ("High", 7.5),      # Software Supply Chain Failures
    "A04:2025": ("High", 7.5),      # Cryptographic Failures
    "A05:2025": ("Critical", 9.1),  # Injection
    "A06:2025": ("Medium", 6.0),    # Insecure Design
    "A07:2025": ("High", 8.0),      # Authentication Failures
    "A08:2025": ("High", 7.5),      # Software or Data Integrity Failures
    "A09:2025": ("Low", 3.5),       # Security Logging and Alerting Failures
    "A10:2025": ("Medium", 5.5),    # Mishandling of Exceptional Conditions
}

_BAND_DOWNGRADE = {"Critical": "High", "High": "Medium", "Medium": "Low", "Low": "Low"}
_DEFAULT_SEVERITY = ("Medium", 5.0)  # only used if a KB entry has neither a known CWE-ID nor OWASP category


@dataclasses.dataclass
class SeverityAssessment:
    cwe_id: str | None
    owasp_category: str | None
    base_band: str
    base_score: float
    margin: float
    low_confidence: bool
    final_band: str
    final_score: float
    rationale: str

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def _lookup_base(cwe_id: str | None, owasp_category: str | None) -> tuple[str, float]:
    if cwe_id and cwe_id in BASE_SEVERITY:
        return BASE_SEVERITY[cwe_id]
    if owasp_category and owasp_category in OWASP_CATEGORY_SEVERITY:
        return OWASP_CATEGORY_SEVERITY[owasp_category]
    return _DEFAULT_SEVERITY


def score_finding(top1: dict, top2: dict | None) -> SeverityAssessment:
    """Score one KB retrieval result (the top-1 match for a code chunk).

    Args:
        top1: the top Security Knowledge Base search result -- a dict with
            'similarity' plus either ('standard'=='CWE', 'cwe_id',
            'owasp_category') or ('standard'=='OWASP', 'code'), matching the
            record shape produced by knowledge_base/build_kb.py.
        top2: the second-best KB search result (used only for its
            'similarity', to compute the confidence margin). None if the KB
            returned fewer than 2 results.
    """
    if top1.get("standard") == "CWE":
        cwe_id = top1.get("cwe_id")
        owasp_category = top1.get("owasp_category")
    else:
        cwe_id = None
        owasp_category = top1.get("code")

    base_band, base_score = _lookup_base(cwe_id, owasp_category)

    margin = (top1["similarity"] - top2["similarity"]) if top2 is not None else 1.0
    low_confidence = margin < MARGIN_CONFIDENCE_THRESHOLD

    label = cwe_id or owasp_category or "unknown weakness"
    if low_confidence:
        final_band = _BAND_DOWNGRADE[base_band]
        final_score = round(max(base_score - 2.0, 0.1), 1)
        rationale = (
            f"Base severity for {label} is {base_band} ({base_score}), but the "
            f"retrieval margin ({margin:.4f}) is below the calibrated confidence "
            f"threshold ({MARGIN_CONFIDENCE_THRESHOLD}) -- the top KB match was not "
            f"clearly separated from the next-closest entry, so the band is "
            f"downgraded one step and flagged for manual/LLM review."
        )
    else:
        final_band = base_band
        final_score = base_score
        rationale = (
            f"Base severity for {label} is {base_band} ({base_score}); retrieval "
            f"margin ({margin:.4f}) exceeds the calibrated confidence threshold "
            f"({MARGIN_CONFIDENCE_THRESHOLD}), so the base severity is kept as-is."
        )

    return SeverityAssessment(
        cwe_id=cwe_id,
        owasp_category=owasp_category,
        base_band=base_band,
        base_score=base_score,
        margin=round(margin, 4),
        low_confidence=low_confidence,
        final_band=final_band,
        final_score=final_score,
        rationale=rationale,
    )
