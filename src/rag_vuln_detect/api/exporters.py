"""Export a scan's findings as JSON, CSV or SARIF 2.1.0 (the interchange format SAST tools and
GitHub code scanning understand)."""

from __future__ import annotations

import csv
import io
import json

_LEVEL = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note"}
CSV_COLUMNS = ["id", "status", "severity", "score", "cwe", "owasp", "file", "start_line", "end_line", "function",
               "llm_confidence", "retrieval_agrees", "explanation", "evidence", "triage"]


def findings_to_csv(findings) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLUMNS)
    for f in findings:
        w.writerow([f.id, f.status, f.severity_band, f.severity_score, f.cwe_id or "", f.owasp_category or "",
                    f.file_path, f.start_line, f.end_line, f.chunk_name, f.llm_confidence if f.llm_confidence is not None else "",
                    "" if f.retrieval_agrees is None else f.retrieval_agrees,
                    (f.llm_explanation or f.rationale or "").replace("\n", " "), (f.llm_evidence or "").replace("\n", " "),
                    f.triage])
    return buf.getvalue()


def findings_to_sarif(findings, scan: dict) -> dict:
    rules, rule_index, results = [], {}, []
    for f in findings:
        rid = f.cwe_id or f.owasp_category or "UNCLASSIFIED"
        if rid not in rule_index:
            rule_index[rid] = len(rules)
            rules.append({"id": rid, "name": rid.replace("-", ""),
                          "shortDescription": {"text": f"{rid} ({f.owasp_category or 'OWASP category unknown'})"},
                          "helpUri": f"https://cwe.mitre.org/data/definitions/{rid.split('-')[-1]}.html" if rid.startswith("CWE-") else "https://owasp.org/Top10/"})
        text = f.llm_explanation or f.rationale or ""
        if f.status == "unverified":
            text = "Unverified retrieval candidate (no LLM verdict). " + text
        results.append({
            "ruleId": rid, "ruleIndex": rule_index[rid], "level": _LEVEL.get(f.severity_band, "note"),
            "message": {"text": text or rid},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.file_path},
                "region": {"startLine": f.start_line or 1, "endLine": f.end_line or f.start_line or 1}}}],
            "properties": {"status": f.status, "severity": f.severity_band, "severityScore": f.severity_score,
                           "llmConfidence": f.llm_confidence, "triage": f.triage, "function": f.chunk_name}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "rag-vuln-detect", "version": "1.0.0", "rules": rules}},
                      "invocations": [{"executionSuccessful": scan.get("status") == "done"}],
                      "results": results}]}


def findings_to_json(findings, scan: dict) -> str:
    out = {"scan": scan, "findings": [f.to_dict() for f in findings]}
    return json.dumps(out, indent=2)
