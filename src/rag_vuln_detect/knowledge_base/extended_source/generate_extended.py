"""
Generates the extended-CWE part of the knowledge base from extended_cwe.psv.

Source format, one weakness per line, 7 pipe-delimited fields:
    CWE-id | name | OWASP Top 10:2025 category | Band:score | description | example pattern | lexical signals

Outputs (all merged idempotently, so this can be re-run after editing the .psv):
    ../kb_entries.json       "cwe_extended" list (retrieval text for the dense + BM25 indexes)
    ../kb_signals.json       project-authored lexical indicators per CWE (BM25 side only)
    ../extended_severity.json  reference severity band/score per CWE (loaded by severity/scorer.py)

Provenance: CWE identifiers and names follow the MITRE CWE catalogue. The descriptions, example patterns, lexical
indicators and reference severities are project-authored from general security knowledge (not copied from MITRE text)
and the OWASP category mapping is the project's own judgment, like the existing 25-entry mapping.

    python src/rag_vuln_detect/knowledge_base/extended_source/generate_extended.py
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
KB = os.path.join(HERE, "..")
BANDS = {"Critical": (9.0, 10.0), "High": (7.0, 8.9), "Medium": (4.0, 6.9), "Low": (0.1, 3.9)}


def parse(path):
    rows, seen = [], set()
    for n, line in enumerate(open(path, encoding="utf-8"), 1):
        line = line.rstrip("\n")
        if not line.strip():
            continue
        f = line.split("|")
        if len(f) != 7:
            sys.exit(f"line {n}: expected 7 fields, got {len(f)}")
        cid, name, owasp, sev, desc, ex, sig = [x.strip() for x in f]
        assert re.fullmatch(r"CWE-\d+", cid), f"line {n}: bad id {cid}"
        assert re.fullmatch(r"A(0[1-9]|10):2025", owasp), f"line {n}: bad OWASP category {owasp}"
        band, score = sev.split(":")
        lo, hi = BANDS[band]
        assert lo <= float(score) <= hi, f"line {n}: score {score} outside band {band}"
        assert cid not in seen, f"duplicate {cid}"
        seen.add(cid)
        rows.append(dict(cwe_id=cid, name=name, owasp_category=owasp, band=band, score=float(score),
                         description=desc, example_pattern=ex, signals=sig))
    return rows


def main():
    rows = parse(os.path.join(HERE, "extended_cwe.psv"))
    kb_path = os.path.join(KB, "kb_entries.json")
    kb = json.load(open(kb_path, encoding="utf-8"))
    core = {e["cwe_id"] for e in kb["cwe_top25_2025"]}
    clash = core & {r["cwe_id"] for r in rows}
    assert not clash, f"already in the Top-25 list: {clash}"
    kb["cwe_extended"] = [{"cwe_id": r["cwe_id"], "name": r["name"], "owasp_category": r["owasp_category"],
                           "description": r["description"], "example_pattern": r["example_pattern"]} for r in rows]
    kb["source_note"] = (kb.get("source_note", "").split(" Extended:")[0] +
                         " Extended: %d further CWE entries relevant to Python/JavaScript/TypeScript code (cwe_extended). "
                         "CWE ids/names follow the MITRE catalogue; descriptions, example patterns and the OWASP category "
                         "mapping are project-authored." % len(rows))
    json.dump(kb, open(kb_path, "w", encoding="utf-8"), indent=2, ensure_ascii=False)

    sp = os.path.join(KB, "kb_signals.json")
    sig = json.load(open(sp, encoding="utf-8"))
    for r in rows:
        sig[r["cwe_id"]] = r["signals"]
    json.dump(sig, open(sp, "w", encoding="utf-8"), indent=2, ensure_ascii=False)

    sev = {r["cwe_id"]: [r["band"], r["score"]] for r in rows}
    json.dump({"_note": "Reference severity per extended CWE (typical weakness-class severity, CVSS v3.1 band thresholds); "
                        "project-authored, see generate_extended.py.", **sev},
              open(os.path.join(KB, "extended_severity.json"), "w", encoding="utf-8"), indent=1)
    print(f"{len(rows)} extended CWE entries written")


if __name__ == "__main__":
    main()
