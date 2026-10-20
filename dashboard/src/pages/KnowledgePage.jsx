import React, { useEffect, useState } from "react";
import { api } from "../api.js";

const GROUPS = [
  ["all", "All"],
  ["owasp", "OWASP Top 10:2025"],
  ["top25", "CWE Top 25:2025"],
  ["extended", "Extended CWEs"],
];

function group(e) {
  if (e.standard === "OWASP") return "owasp";
  return e.tier === "extended" ? "extended" : "top25";
}

export default function KnowledgePage() {
  const [entries, setEntries] = useState([]);
  const [q, setQ] = useState("");
  const [g, setG] = useState("all");
  useEffect(() => { api("/knowledge-base").then((r) => setEntries(r.entries)); }, []);
  const count = (k) => (k === "all" ? entries.length : entries.filter((e) => group(e) === k).length);
  const needle = q.toLowerCase();
  const shown = entries.filter((e) => (g === "all" || group(e) === g)
    && `${e.cwe_id || e.code} ${e.name} ${e.description} ${e.owasp_category || ""}`.toLowerCase().includes(needle));
  return (
    <>
      <h1>Security knowledge base</h1>
      <p className="sub">
        The standards text the retriever searches: {entries.length} entries covering the OWASP Top 10:2025 categories, the CWE Top 25:2025
        and {count("extended")} further CWEs relevant to application code in the supported languages. Each scanned code unit is matched against these.
      </p>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginBottom: 12 }}>
        <div className="seg">
          {GROUPS.map(([k, label]) => (
            <button key={k} className={g === k ? "on" : ""} onClick={() => setG(k)}>{label} ({count(k)})</button>))}
        </div>
        <input type="search" placeholder="Filter entries (id, name, text)" value={q} onChange={(e) => setQ(e.target.value)} style={{ maxWidth: 300 }} aria-label="Filter" />
      </div>
      <p className="muted" style={{ marginTop: 0 }}>Showing {shown.length}. Extended entries: CWE ids and names follow MITRE; descriptions are project-written.</p>
      <div className="card table-wrap"><table>
        <thead><tr><th>ID</th><th>Name</th><th>OWASP</th><th>Description</th></tr></thead>
        <tbody>{shown.map((e) => (
          <tr key={e.cwe_id || e.code}><td><b>{e.cwe_id || e.code}</b></td><td>{e.name}</td><td>{e.owasp_category || (e.standard === "OWASP" ? "category" : "")}</td><td className="muted">{e.description}</td></tr>))}</tbody>
      </table></div>
    </>
  );
}
