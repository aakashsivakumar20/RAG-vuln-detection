"""
Severity Scoring module (docs/chapter3_methodology.md, §3.3).

Rule-based, CVSS-inspired severity, deliberately NOT decided by the LLM: the LLM supplies a
verdict (is this exploitable? which CWE? how confident?) and this module turns that into an
auditable severity band, so the number cannot drift with prompt wording.

Two scoring paths
-----------------
score_verdict()  - the main path, used when the LLM judged the chunk (pipeline/scan.py).
    * not vulnerable            -> status "rejected", band "None".
    * vulnerable, confident     -> status "confirmed"; band/score from the per-CWE reference table
                                   (BASE_SEVERITY) for the CWE the LLM chose.
    * vulnerable, low confidence-> status "needs_review"; band downgraded one step.
    LLM confidence below LLM_CONFIDENCE_THRESHOLD counts as low.

score_finding()  - the fallback used when no LLM verdict exists (no key, or provider failure). It scores
    the retrieval top-1 candidate and produces status "unverified": "IF this candidate is a true
    positive, THEN this is its estimated severity". The retrieval margin (fused score of top-1
    minus top-2) is a confidence proxy; below MARGIN_CONFIDENCE_THRESHOLD the band is downgraded
    one step and the finding is flagged low-confidence.

Reference severities (BASE_SEVERITY / OWASP_CATEGORY_SEVERITY) are this project's own deterministic
lookup, following CVSS v3.1 band thresholds (0.1-3.9 Low, 4.0-6.9 Medium, 7.0-8.9 High, 9.0-10.0
Critical). They describe the *typical* severity of a weakness class, not a per-instance CVSS vector
(that would need attack-vector / privileges / impact analysis of the running system).
"""

from __future__ import annotations

import dataclasses

# Margin threshold for the FUSED (hybrid dense+BM25, min-max normalised) retrieval score, used only on the
# no-LLM fallback path. 0.15 was set on the DEV benchmark and kept after the knowledge base grew from 35 to 269
# entries because no other round value did clearly better there (dev: precision when confident 10/12 = 83%).
# With the larger KB the signal is WEAK and is reported as such, not tuned on held-out: held-out precision when
# confident is 6/12 = 50%, mean margin 0.149 when top-1 is right vs 0.106 when wrong; 17 of 23 wrong top-1 matches
# fall below the threshold, but so do 9 of 15 correct ones (results/margin_calibration.json). With an LLM
# verdict (the main path) the LLM's own confidence is used instead.
MARGIN_CONFIDENCE_THRESHOLD = 0.15

# An LLM verdict whose self-reported confidence is below this goes to human review
# and has its severity band downgraded one step (see score_verdict).
LLM_CONFIDENCE_THRESHOLD = 0.70

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

# Extended catalogue (knowledge_base/extended_severity.json, generated with the extended KB entries). The
# hand-set table above wins if both define a CWE.
def _load_extended_severity() -> dict[str, tuple[str, float]]:
    import json
    import os
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "knowledge_base", "extended_severity.json")
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError):
        return {}
    return {k: (v[0], float(v[1])) for k, v in raw.items() if not k.startswith("_")}


for _cwe, _sev in _load_extended_severity().items():
    BASE_SEVERITY.setdefault(_cwe, _sev)

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
    # --- added with the LLM verdict step (defaults keep retrieval-only callers unchanged)
    status: str = "unverified"         # unverified | confirmed | needs_review | rejected
    llm_confidence: float | None = None
    retrieval_agrees: bool | None = None

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


# --------------------------------------------------------------------- LLM verdicts

def _owasp_for_cwe(cwe_id: str | None, kb_hits: list[dict] | None, kb_lookup: dict | None) -> str | None:
    for h in kb_hits or []:
        if h.get("cwe_id") == cwe_id and h.get("owasp_category"):
            return h["owasp_category"]
    return (kb_lookup or {}).get(cwe_id)


def score_verdict(verdict, kb_hits: list[dict] | None = None, kb_lookup: dict | None = None) -> SeverityAssessment:
    """Severity for a chunk the LLM has judged (status 'ok' verdicts only).

    * not vulnerable            -> status 'rejected' (a retrieval false positive that the
                                   LLM filtered out); band 'None', score 0.
    * vulnerable, confident     -> status 'confirmed'; band from the per-CWE reference table
                                   for the CWE the LLM chose.
    * vulnerable, low confidence-> status 'needs_review'; band downgraded one step.
    `retrieval_agrees` records whether the LLM's CWE is among the top-3 retrieved KB
    entries (a cheap consistency signal that is shown to the reviewer, not used to
    override the model).
    """
    top_ids = [h.get("cwe_id") for h in (kb_hits or [])[:3]]
    conf = verdict.confidence if verdict.confidence is not None else 0.5
    if not verdict.vulnerable:
        return SeverityAssessment(
            cwe_id=None, owasp_category=None, base_band="None", base_score=0.0, margin=0.0,
            low_confidence=False, final_band="None", final_score=0.0,
            rationale=("The LLM reviewed the retrieved weakness candidate and judged the code not exploitable: "
                       + (verdict.explanation or "no explanation given")),
            status="rejected", llm_confidence=conf, retrieval_agrees=None)

    cwe_id = verdict.cwe_id
    owasp = _owasp_for_cwe(cwe_id, kb_hits, kb_lookup)
    if cwe_id is None and kb_hits:           # vulnerable but no CWE named: fall back to retrieval's guess
        cwe_id = kb_hits[0].get("cwe_id")
        owasp = kb_hits[0].get("owasp_category") or kb_hits[0].get("code")
    base_band, base_score = _lookup_base(cwe_id, owasp)
    agrees = (cwe_id in top_ids) if cwe_id else None
    low = conf < LLM_CONFIDENCE_THRESHOLD
    label = cwe_id or owasp or "unknown weakness"
    if low:
        band, score, status = _BAND_DOWNGRADE[base_band], round(max(base_score - 2.0, 0.1), 1), "needs_review"
        why = (f"LLM flagged {label} but with confidence {conf:.2f} (< {LLM_CONFIDENCE_THRESHOLD}); "
               f"reference severity {base_band} ({base_score}) is downgraded one step and the finding needs human review.")
    else:
        band, score, status = base_band, base_score, "confirmed"
        why = (f"LLM confirmed {label} with confidence {conf:.2f}; reference severity {base_band} ({base_score}) applies.")
    if agrees is False:
        why += " The CWE chosen by the LLM was not among the top-3 retrieved knowledge-base entries."
    return SeverityAssessment(
        cwe_id=cwe_id, owasp_category=owasp, base_band=base_band, base_score=base_score, margin=0.0,
        low_confidence=low, final_band=band, final_score=score, rationale=why,
        status=status, llm_confidence=conf, retrieval_agrees=agrees)
