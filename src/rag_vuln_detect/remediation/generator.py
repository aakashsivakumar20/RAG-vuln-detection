"""
Remediation Generation module (per docs/chapter3_methodology.md §3.3, and the
Review 2 design principle recorded in session-log/SESSION_LOG.md: "Remediation
suggestions are always shown as a before/after diff for developer review --
never auto-applied").

Two complementary fix sources
-----------------------------
1. This module: a deterministic, CWE-keyed template layer. For CWE categories with a well-established
   mechanical fix (parameterised queries for CWE-89, an `os.path.commonpath` confinement check for
   CWE-22, an argument list instead of a shell string for CWE-78, ...) it returns an illustrative
   before/after pair plus a plain-language explanation. It never guesses: categories without a
   template return None (NO_TEMPLATE_AVAILABLE) - e.g. CWE-306 / CWE-863, which need reasoning
   about the specific application.
2. The LLM Security Analysis module (llm/analyzer.py) proposes a corrected version of the *actual*
   chunk. pipeline/scan.py stores both; the dashboard shows them side by side.

Every remediation returned by this module is a suggestion for a human
developer to review and apply -- it is never written back to the scanned
repository automatically (see pipeline/scan.py).
"""

from __future__ import annotations

import dataclasses

from rag_vuln_detect.remediation.fix_catalog import ALIASES, CATALOG
from rag_vuln_detect.retrieval.patterns import LANG_TAG


@dataclasses.dataclass
class Remediation:
    cwe_id: str
    title: str
    explanation: str
    before: str
    after: str
    steps: list = dataclasses.field(default_factory=list)   # plain-language "how to fix" checklist
    reference: str = ""                                      # where to read more
    language: str = "py"                                     # tag of the example shown (py, js, java, php, go, cs, rb, c, rs, kt)
    languages: list = dataclasses.field(default_factory=list)  # tags this pattern has examples for


# The templates live in fix_catalog.py (about 45 weakness types, per-language examples).
# CWE IDs for which the KB has an entry but no mechanical template exists --
# these genuinely need LLM reasoning about business logic / auth flow, not a
# pattern substitution. Kept explicit (rather than silently returning None)
# so this list itself is documentation of scope.
NO_TEMPLATE_AVAILABLE = frozenset({
    "CWE-401", "CWE-427", "CWE-668", 
})


def has_template(cwe_id: str | None) -> bool:
    return bool(cwe_id) and (cwe_id in CATALOG or cwe_id in ALIASES)


def generate_remediation(cwe_id: str | None, language: str | None = None) -> Remediation | None:
    """Return a template-based remediation for cwe_id in the given language (falls back to the Python
    example, then to the first available one), or None if this CWE has no template."""
    if not cwe_id:
        return None
    key = ALIASES.get(cwe_id, cwe_id)
    entry = CATALOG.get(key)
    if entry is None:
        return None
    variants = entry["variants"]
    tag = LANG_TAG.get((language or "").lower(), "py") if language else "py"
    if tag not in variants:
        tag = "py" if "py" in variants else ("js" if "js" in variants else next(iter(variants)))
    before, after = variants[tag]
    return Remediation(cwe_id=cwe_id, title=entry["title"], explanation=entry["explanation"], before=before,
                       after=after, steps=list(entry["steps"]), reference=entry["reference"], language=tag,
                       languages=list(variants))


def template_cwe_ids() -> list[str]:
    return sorted(set(CATALOG) | set(ALIASES))


def coverage_summary() -> dict:
    """How many CWE categories have a real template (for honest reporting)."""
    templated = set(template_cwe_ids())
    return {
        "templated_count": len(templated),
        "base_patterns": len(CATALOG),
        "no_template_count": len(NO_TEMPLATE_AVAILABLE),
        "templated_cwe_ids": sorted(templated),
    }
