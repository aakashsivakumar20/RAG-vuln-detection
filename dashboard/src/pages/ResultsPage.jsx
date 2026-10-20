import React, { useEffect, useMemo, useRef, useState } from "react";
import { api, SEVERITIES, STATUS_LABEL, fmtDuration, repoName, owaspLabel } from "../api.js";
import { SevPill, StatusPill, Tile, BarList, StackBar, statusColor, LangBadge } from "../components/bits.jsx";
import { Stages, eta } from "../components/RunStatus.jsx";
import { IconDownload, IconWrench, IconCheck } from "../components/icons.jsx";
import FindingDrawer from "../components/FindingDrawer.jsx";

const SEV_COLOR = { Critical: "var(--sev-critical)", High: "var(--sev-high)", Medium: "var(--sev-medium)", Low: "var(--sev-low)" };
const ROW_LIMIT = 150;

export default function ResultsPage({ scanId, llm }) {
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [err, setErr] = useState("");
  const [sev, setSev] = useState("all");
  const [status, setStatus] = useState("all");
  const [cwe, setCwe] = useState("");
  const [showRejected, setShowRejected] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(null);
  const [flash, setFlash] = useState({});
  const prevStatus = useRef({});
  const timer = useRef(null);
  const alive = useRef(true);

  const load = async () => {
    try {
      const s = await api(`/scans/${scanId}`);
      const f = await api(`/scans/${scanId}/findings?include_rejected=${showRejected ? 1 : ""}`);
      if (!alive.current) return;
      // highlight rows whose status just changed (pending -> verdict)
      const changed = {};
      for (const r of f.findings) {
        const was = prevStatus.current[r.id];
        if (was && was !== r.status) changed[r.id] = true;
        prevStatus.current[r.id] = r.status;
      }
      if (Object.keys(changed).length) {
        setFlash((x) => ({ ...x, ...changed }));
        setTimeout(() => alive.current && setFlash((x) => { const n = { ...x }; Object.keys(changed).forEach((k) => delete n[k]); return n; }), 1700);
      }
      setScan(s); setFindings(f.findings);
      if (s.status !== "running" && timer.current) { clearInterval(timer.current); timer.current = null; }
    } catch (e) { if (alive.current) setErr(e.message); }
  };
  useEffect(() => {
    alive.current = true; load();
    timer.current = setInterval(load, 1000);
    return () => { alive.current = false; timer.current && clearInterval(timer.current); };
  }, [showRejected]);

  const shown = useMemo(() => findings.filter((f) =>
    (sev === "all" || f.severity_band === sev) && (status === "all" || f.status === status) && (!cwe || f.cwe_id === cwe) &&
    (!q || `${f.file_path} ${f.chunk_name} ${f.cwe_id} ${f.owasp_category || ""} ${f.llm_explanation || ""}`.toLowerCase().includes(q.toLowerCase()))),
  [findings, sev, status, cwe, q]);

  if (err) return <div className="banner err">{err} <a href="#/">Back</a></div>;
  if (!scan) return <div className="skeleton"><span className="shimmer" /><span className="shimmer" /><span className="shimmer" /></div>;

  const c = scan.counts || {};
  const bs = scan.by_status || {};
  const bySev = scan.by_severity || {};
  const running = scan.status === "running";
  const llmMode = scan.mode !== "retrieval-only";
  const pending = bs.pending || 0;
  const verdicts = (bs.confirmed || 0) + (bs.needs_review || 0) + (bs.rejected || 0);
  const rejectRate = verdicts ? Math.round(((bs.rejected || 0) / verdicts) * 100) : null;
  const reported = (bs.confirmed || 0) + (bs.needs_review || 0);
  const secsLeft = running ? eta(scan) : null;
  const withFix = findings.filter((f) => f.has_remediation && f.status !== "rejected" && f.status !== "pending").length;
  const exportLink = (fmt) => `/api/scans/${scanId}/export?format=${fmt}`;
  const rows = showAll ? shown : shown.slice(0, ROW_LIMIT);
  const countBy = (fn) => findings.filter(fn).length;

  const badge = running ? <span className="live-badge"><span className="pulse" />Scanning live</span>
    : scan.status === "done" ? <span className="live-badge done"><span className="pulse" />Complete</span>
    : scan.status === "cancelled" ? <span className="live-badge bad"><span className="pulse" />Cancelled</span>
    : <span className="live-badge bad"><span className="pulse" />Failed</span>;

  return (
    <>
      <div className="runhead">
        <div style={{ minWidth: 0 }}>
          <div className="repo-title"><h1 title={scan.repo_url}>{repoName(scan.repo_url)}</h1>{badge}</div>
          <div className="meta">
            <span className="mono" title={scan.repo_url} style={{ maxWidth: 420, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{scan.repo_url}</span>
            <span>Scan #{scan.id}</span>
            <span>{llmMode ? `${scan.provider}${scan.model ? " / " + scan.model : ""}` : "retrieval only (no LLM)"}</span>
            <span>{fmtDuration(scan.elapsed_s)}{running ? " elapsed" : ""}</span>
            {c.files_analysable != null && <span>{c.files_analysable} files · {c.chunks_total || 0} code units</span>}
          </div>
        </div>
        <div className="row no-print" style={{ gap: 8 }}>
          {running && <button className="danger" onClick={() => api(`/scans/${scanId}/cancel`, { method: "POST", body: {} }).catch((e) => setErr(e.message))}>Cancel scan</button>}
          {scan.status !== "running" && (
            <>
              <a href={exportLink("json")}><button className="small"><IconDownload width={13} height={13} /> JSON</button></a>
              <a href={exportLink("csv")}><button className="small"><IconDownload width={13} height={13} /> CSV</button></a>
              <a href={exportLink("sarif")}><button className="small"><IconDownload width={13} height={13} /> SARIF</button></a>
              <button className="small" onClick={() => window.print()}>Print / PDF</button>
            </>
          )}
          <a href="#/"><button className="small primary">New scan</button></a>
        </div>
      </div>

      {(running || scan.status === "cancelled") && (
        <div className="card" aria-live="polite">
          <Stages scan={scan} />
          <div className={`progress ${running && !scan.stage ? "indet" : ""}`}><div style={{ width: `${Math.round(scan.progress * 100)}%` }} /></div>
          <div className="runmsg">
            <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{scan.message || "Starting..."}</span>
            <span className="num" style={{ flex: "none" }}>{Math.round(scan.progress * 100)}%{secsLeft != null && pending > 0 ? ` · about ${fmtDuration(secsLeft)} left` : ""}</span>
          </div>
          {c.triage_ready_s != null && pending > 0 && (
            <div className="banner info" style={{ marginTop: 12, marginBottom: 0 }}>
              <b>{(bs.pending || 0) + verdicts + (bs.unverified || 0)} candidates were ranked in {c.triage_ready_s}s.</b> They are listed below now; the LLM is verifying them from most to least suspicious, and each row updates when its verdict arrives. Severity marked with ? is an estimate from retrieval only.
            </div>)}
        </div>
      )}
      {scan.status === "failed" && <div className="banner err"><b>Scan failed:</b> {scan.error}</div>}
      {scan.status === "cancelled" && <div className="banner info">Scan was cancelled; candidates the LLM had not judged are shown as unverified.</div>}
      {scan.status === "done" && scan.error && <div className="banner warn">{scan.error}{!llmMode && <> <a href="#/settings">Open settings</a></>}</div>}
      {!llmMode && !running && (
        <div className="banner info"><b>Unverified candidates.</b> These are code units that most resemble a known weakness class; no LLM has judged them, so they are <b>not</b> confirmed vulnerabilities.</div>
      )}

      {!running && llmMode && scan.status === "done" && (
        <p className="summaryline">
          {reported > 0
            ? <><b>{reported} issue{reported === 1 ? "" : "s"} found</b>{(bySev.Critical || 0) + (bySev.High || 0) > 0 ? <> ({[bySev.Critical && `${bySev.Critical} critical`, bySev.High && `${bySev.High} high`].filter(Boolean).join(", ")})</> : null}
              {" "}across {Object.keys(scan.by_file || {}).length} file{Object.keys(scan.by_file || {}).length === 1 ? "" : "s"}; </>
            : <><b>No vulnerabilities confirmed</b>; </>}
          the LLM rejected {bs.rejected || 0} false-positive candidate{(bs.rejected || 0) === 1 ? "" : "s"}. {withFix} finding{withFix === 1 ? " has" : "s have"} a fix ready.
          {c.triage_ready_s != null && <> Candidates were ranked in {c.triage_ready_s}s; the full scan took {fmtDuration(scan.elapsed_s)}.</>}
        </p>)}

      <div className="kpis">
        <div className="card kcard">
          <div className="row" style={{ justifyContent: "space-between", marginBottom: 10 }}>
            <h2 style={{ margin: 0 }}>{llmMode ? (running ? "Verified so far" : "Findings") : "Candidates"} by severity</h2>
            {pending > 0 && <span className="muted" style={{ fontSize: 12 }}>{pending} still being verified</span>}
          </div>
          <div className="sevstrip">
            {SEVERITIES.map((sv) => (
              <div key={sv} className={`sevcell sev-${sv}`}><div className="v num">{bySev[sv] || 0}</div><div className="l">{sv}</div></div>
            ))}
          </div>
        </div>
        <div className="tiles compact">
          <Tile value={bs.confirmed || 0} label="Confirmed" note="LLM: vulnerable, confident" color="var(--s-confirmed)" />
          <Tile value={bs.needs_review || 0} label="Needs review" note="LLM: vulnerable, low confidence" color="var(--s-review)" />
          {llmMode && <Tile value={bs.rejected || 0} label="Rejected" note={rejectRate != null ? `${rejectRate}% of judged units were false positives` : "false positives filtered out"} color="var(--s-rejected)" />}
          {(pending > 0 || running) && <Tile value={pending} label="Verifying" note="waiting for the LLM" color="var(--s-pending)" />}
          {(!llmMode || (bs.unverified || 0) > 0) && <Tile value={bs.unverified || 0} label="Unverified" note={llmMode ? "LLM verdict unavailable" : "retrieval candidates only"} color="var(--s-unverified)" />}
          <Tile value={withFix} label="Fix ready" note="LLM fix and / or standard pattern" color="var(--ok)" />
          <Tile value={c.llm_calls ?? 0} label="LLM calls" note={`${c.llm_cache_hits || 0} served from cache`} />
          {(c.llm_tokens_in || c.llm_tokens_out) ? <Tile value={`${Math.round(((c.llm_tokens_in || 0) + (c.llm_tokens_out || 0)) / 1000)}K`} label="Tokens used" note={`${Math.round((c.llm_tokens_in || 0) / 1000)}K in, ${Math.round((c.llm_tokens_out || 0) / 1000)}K out${c.llm_models_used ? " · " + Object.entries(c.llm_models_used).map(([m, n]) => `${m.split("/").pop()} x${n}`).join(", ") : ""}`} /> : null}
        </div>
      </div>

      <div className="card">
        <div className="filters">
          <input type="search" placeholder="Search file, function, CWE, explanation" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search findings" />
          <div className="seg" role="group" aria-label="Severity">
            {["all", ...SEVERITIES].map((s) => (
              <button key={s} className={sev === s ? "on" : ""} onClick={() => setSev(s)}>
                {s === "all" ? "All" : s}<span className="ct">{s === "all" ? findings.length : countBy((f) => f.severity_band === s)}</span>
              </button>))}
          </div>
          <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status" style={{ width: "auto" }}>
            <option value="all">All statuses</option>
            {["confirmed", "needs_review", "pending", "unverified", "rejected"].map((s) => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
          </select>
          {cwe && <button className="small" onClick={() => setCwe("")}>{cwe} ✕</button>}
          {llmMode && <label><input type="checkbox" checked={showRejected} onChange={(e) => setShowRejected(e.target.checked)} /> Show rejected</label>}
          <span className="muted">{shown.length} shown</span>
        </div>
        {shown.length === 0 ? <div className="empty">{running ? "Fetching and parsing the repository... candidates appear here as soon as retrieval finishes." : "No findings match the filters."}</div> : (
          <div className="table-wrap"><table className="ftable">
            <thead><tr><th>Severity</th><th>Weakness</th><th>Location</th><th>Verdict</th><th>Fix</th></tr></thead>
            <tbody>
              {rows.map((f) => {
                const isPending = f.status === "pending";
                return (
                  <tr key={f.id} className={`click r-${f.status === "rejected" ? "None" : f.severity_band} ${isPending ? "pending" : ""} ${flash[f.id] ? "flash" : ""} ${open === f.id ? "sel" : ""}`}
                    onClick={() => setOpen(f.id)} tabIndex={0} onKeyDown={(e) => e.key === "Enter" && setOpen(f.id)}>
                    <td><SevPill band={f.severity_band} estimated={isPending} />{!isPending && f.severity_band !== "None" && <span className="muted num" style={{ marginLeft: 8 }}>{f.severity_score}</span>}</td>
                    <td><span className="cwe-tag">{f.cwe_id || "-"}</span>{f.owasp_category && <span className="owasp">{owaspLabel(f.owasp_category)}</span>}</td>
                    <td><div className="floc"><span className="path"><LangBadge path={f.file_path} />{f.file_path}:{f.start_line}</span><span className="fn">{f.chunk_name}</span></div></td>
                    <td>
                      <StatusPill status={f.status} />
                      {f.llm_confidence != null && <span className="conf" style={{ marginLeft: 10 }}><span className="meter"><div style={{ width: `${f.llm_confidence * 100}%` }} /></span>{f.llm_confidence.toFixed(2)}</span>}
                      {f.triage && <span className="muted" style={{ marginLeft: 8, fontSize: 12 }}>{f.triage === "accepted" ? "Accepted" : "False positive"}</span>}
                    </td>
                    <td>{f.status === "rejected" ? <span className="muted">-</span> : f.has_remediation
                      ? <span className="fixcol yes"><IconWrench width={14} height={14} />{isPending ? "pattern" : "ready"}</span>
                      : <span className="fixcol">{isPending ? <span className="shimmer" /> : "-"}</span>}</td>
                  </tr>
                );
              })}
            </tbody>
          </table></div>
        )}
        {shown.length > rows.length && <div style={{ textAlign: "center", marginTop: 12 }}><button onClick={() => setShowAll(true)}>Show all {shown.length} findings</button></div>}
      </div>
      <div className="chart-grid three">
        <div className="card">
          <h2>Outcome of analysed code units</h2>
          <StackBar parts={[
            { label: "Confirmed", value: bs.confirmed || 0, color: statusColor("confirmed") },
            { label: "Needs review", value: bs.needs_review || 0, color: statusColor("needs_review") },
            { label: "Rejected", value: bs.rejected || 0, color: statusColor("rejected") },
            { label: "Verifying", value: pending, color: statusColor("pending") },
            { label: "Unverified", value: bs.unverified || 0, color: statusColor("unverified") },
          ]} />
          <h2 style={{ marginTop: 18 }}>OWASP Top 10 categories</h2>
          <BarList items={Object.entries(scan.by_owasp || {}).slice(0, 6).map(([k, v]) => ({ label: owaspLabel(k), title: `${owaspLabel(k)}: ${v}`, value: v }))} empty="No categories yet" />
        </div>
        <div className="card">
          <h2>Weakness classes (CWE) <span className="muted" style={{ fontWeight: 400, fontSize: 12 }}>click to filter</span></h2>
          <BarList items={Object.entries(scan.by_cwe || {}).slice(0, 10).map(([k, v]) => ({ label: k, value: v }))} empty="No weaknesses yet"
            onPick={(k) => setCwe(cwe === k ? "" : k)} active={cwe} />
        </div>
        <div className="card">
          <h2>Files with the most findings</h2>
          <BarList items={Object.entries(scan.by_file || {}).slice(0, 8).map(([k, v]) => ({ label: k.split("/").slice(-2).join("/"), title: `${k}: ${v}`, value: v }))}
            empty="No files yet" color="var(--accent-2)" onPick={(k) => { const full = Object.keys(scan.by_file || {}).find((p) => p.endsWith(k)); setQ(q === full ? "" : full || k); }} />
        </div>
      </div>

      {open && <FindingDrawer id={open} ids={shown.map((f) => f.id)} onNavigate={setOpen} onClose={() => setOpen(null)} onChanged={load} />}
    </>
  );
}
