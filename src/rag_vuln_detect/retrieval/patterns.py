"""
Static "sink" rules: regular expressions for well-known dangerous API usages and code idioms, each tied to a CWE.

These work like the rule packs of simple static-analysis tools. A bag-of-words retriever sees `os.system` and `ping`
as two unrelated words; a rule sees `os.system(<string concatenation>)` as one concrete idiom and says CWE-78 with
high confidence. Rule hits are one input to the hybrid retriever (retrieval/hybrid.py); they are also shown in the
dashboard Inspector so the reviewer can see exactly which rule fired on which line.

Rules live in knowledge_base/sink_rules.tsv (one per line, tab separated):

    id  cwe  langs  weight  requires  unless  regex  note

* langs    comma list of: py js java php go cs rb c rs kt, or `*` for every language
* weight   0-1, how strongly a hit points to that CWE (0.9 = near-certain sink, 0.3 = weak context)
* requires optional second regex that must ALSO match somewhere in the code ("-" = none)
* unless   optional regex whose presence cancels the rule, e.g. a sanitiser or an authorisation check ("-" = none)

The rules are project-authored from general knowledge of vulnerable APIs. A rule firing is evidence, not a verdict:
patched code that still contains the API also fires, which is why the LLM verdict step follows retrieval.
"""

from __future__ import annotations

import dataclasses
import os
import re

_HERE = os.path.dirname(os.path.abspath(__file__))
RULES_PATH = os.path.join(_HERE, "..", "knowledge_base", "sink_rules.tsv")
# rules for the languages added in v2 live in a second file so the original Python/JavaScript rule set stays untouched
RULES_PATH_OTHER_LANGS = os.path.join(_HERE, "..", "knowledge_base", "sink_rules_other_langs.tsv")

# chunk.language / snippet language name -> short rule tag
LANG_TAG = {
    "python": "py", "py": "py",
    "javascript": "js", "typescript": "js", "js": "js", "jsx": "js", "ts": "js", "tsx": "js",
    "java": "java", "php": "php", "go": "go", "golang": "go", "csharp": "cs", "c#": "cs", "cs": "cs",
    "ruby": "rb", "rb": "rb", "c": "c", "cpp": "c", "c++": "c", "rust": "rs", "rs": "rs",
    "kotlin": "kt", "kt": "kt",
}


@dataclasses.dataclass
class Rule:
    id: str
    cwe: str
    langs: frozenset
    weight: float
    requires: "re.Pattern | None"
    unless: "re.Pattern | None"
    regex: "re.Pattern"
    note: str
    source: str = ""          # the raw regex text, shown in the Inspector

    def applies_to(self, tag: str | None) -> bool:
        return tag is None or "*" in self.langs or tag in self.langs


@dataclasses.dataclass
class RuleHit:
    rule: Rule
    line: int
    text: str


def _compile(p: str) -> "re.Pattern | None":
    p = p.strip()
    return None if p in ("", "-") else re.compile(p, re.MULTILINE)


def load_rules(path: str | None = None) -> list[Rule]:
    """All rules: the Python/JavaScript file plus the other-languages file (or just `path` when given)."""
    if path is not None:
        return _load_file(path)
    return _load_file(RULES_PATH) + _load_file(RULES_PATH_OTHER_LANGS)


def _load_file(path: str) -> list[Rule]:
    rules: list[Rule] = []
    if not os.path.exists(path):
        return rules
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 7:
                raise ValueError(f"{os.path.basename(path)} line {n}: expected 8 tab-separated fields, got {len(parts)}")
            rid, cwe, langs, weight, requires, unless, regex = parts[:7]
            note = parts[7] if len(parts) > 7 else ""
            rules.append(Rule(id=rid.strip(), cwe=cwe.strip(), langs=frozenset(x.strip() for x in langs.split(",")),
                              weight=float(weight), requires=_compile(requires), unless=_compile(unless),
                              regex=re.compile(regex, re.MULTILINE), note=note.strip(), source=regex))
    return rules


_COMMENT_RE = re.compile(r"^[ \t]*(#|//|\*|/\*).*$", re.MULTILINE)


def strip_comments(code: str) -> str:
    """Drop whole-line comments so that prose such as '# never use eval()' does not fire a rule."""
    return _COMMENT_RE.sub("", code)


def scan(code: str, language: str | None, rules: list[Rule]) -> list[RuleHit]:
    tag = LANG_TAG.get((language or "").lower()) if language else None
    text = strip_comments(code)
    hits: list[RuleHit] = []
    for r in rules:
        if not r.applies_to(tag):
            continue
        m = r.regex.search(text)
        if not m:
            continue
        if r.requires is not None and not r.requires.search(text):
            continue
        if r.unless is not None and r.unless.search(text):
            continue
        line = text.count("\n", 0, m.start()) + 1
        snippet = (m.group(0).strip().splitlines() or [""])[0][:140]
        hits.append(RuleHit(r, line, snippet))
    return hits


def cwe_scores(hits: list[RuleHit]) -> dict[str, float]:
    """Combine the rules that fired for one CWE as independent evidence: 1 - prod(1 - weight)."""
    miss: dict[str, float] = {}
    for h in hits:
        miss[h.rule.cwe] = miss.get(h.rule.cwe, 1.0) * (1.0 - h.rule.weight)
    return {cwe: round(1.0 - m, 4) for cwe, m in miss.items()}
