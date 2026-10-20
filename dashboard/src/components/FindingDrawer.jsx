import React, { useEffect, useRef, useState } from "react";
import { api, diffLines, owaspLabel } from "../api.js";
import { StatusPill, CodeBlock, CopyButton, LangBadge } from "./bits.jsx";
import { IconWrench, IconCheck, IconAlert } from "./icons.jsx";

const LANG_NAME = { py: "Python", js: "JavaScript", java: "Java", php: "PHP", go: "Go", cs: "C#", rb: "Ruby", c: "C", rs: "Rust", kt: "Kotlin" };

function Diff({ before, after }) {
  const d = diffLines(before, after);
  const marks = d.map((x) => (x.t === "add" ? "add" : x.t === "del" ? "del" : ""));
  const code = d.map((x) => (x.t === "add" ? "+ " : x.t === "del" ? "- " : "  ") + x.s).join("\n");
  return <CodeBlock code={code} marks={marks} copy={after} />;
}

function hotMarks(code, evidence) {
  const ev = (evidence || "").trim().replace(/^[`'"]+|[`'"]+$/g, "");
  if (ev.length < 6) return null;
  const lines = (code || "").split("\n");
  const first = ev.split("\n")[0].trim();
  const marks = lines.map((l) => (first && l.includes(first) ? "hot" : ""));
  return marks.some(Boolean) ? marks : null;
}

export default function FindingDrawer({ id, ids = [], onNavigate, onClose, onChanged }) {
  const [f, setF] = useState(null);
  const [err, setErr] = useState("");
  const [tab, setTab] = useState("overview");
  const [fixTab, setFixTab] = useState("llm");
  const [note, setNote] = useState("");
  const poll = useRef(null);

  const load = (first) => api(`/findings/${id}`).then((x) => {
    setF(x);
    if (first) { setNote(x.triage_note || ""); setFixTab(x.remediation && x.remediation.llm ? "llm" : "template"); }
    return x;
  }).catch((e) => setErr(e.message));

  const pos = ids.indexOf(id);
  const go = (d) => { const n = ids[pos + d]; if (n != null && onNavigate) onNavigate(n); };

  useEffect(() => {
    setF(null); setErr(""); setTab("overview");
    load(true);
    const key = (e) => {
      if (e.target && /INPUT|TEXTAREA|SELECT/.test(e.target.tagName)) return;
      if (e.key === "Escape") onClose(); else if (e.key === "ArrowDown" || e.key === "j") go(1); else if (e.key === "ArrowUp" || e.key === "k") go(-1);
    };
    window.addEventListener("keydown", key);
    return () => { window.removeEventListener("keydown", key); clearInterval(poll.current); };
  }, [id]);

  // a pending finding updates itself when its verdict arrives
  useEffect(() => {
    clearInterval(poll.current);
    if (f && f.status === "pending") poll.current = setInterval(async () => { const x = await load(false); if (x && x.status !== "pending") { setFixTab(x.remediation && x.remediation.llm ? "llm" : "template"); onChanged && onChanged(); } }, 1200);
    return () => clearInterval(poll.current);
  }, [f && f.status]);

  const triage = async (value) => {
    try { setF(await api(`/findings/${id}`, { method: "PATCH", body: { triage: value, note } })); onChanged && onChanged(); } catch (e) { setErr(e.message); }
  };

  const rem = f && f.remediation;
  const tpl = rem && rem.template;
  const llmFix = rem && rem.llm;
  const kbName = f && (f.retrieved_kb_context || []).find((h) => h.id === f.cwe_id);
  const sevVar = f ? `var(--sev-${(f.severity_band || "None").toLowerCase()})` : undefined;
  const tabs = [["overview", "Overview"], ["fix", "Fix"], ["evidence", "Evidence"], ["review", "Review"]];

  return (
    <>
      <div className="drawer-bg" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="Finding details">
        <div className="dhead">
          <div className="top">
            <div style={{ minWidth: 0 }}>
              {f ? (
                <>
                  <div className="row" style={{ gap: 10 }}>
                    {f.status === "pending" ? <span className="pill status-pending"><span className="spinner" />Verifying with the LLM</span>
                      : f.severity_band !== "None" ? <span className={`sevbadge sev-${f.severity_band}`}><span className="score">{f.severity_score}</span><span className="band">{f.severity_band}</span></span> : null}
                    <StatusPill status={f.status} />
                  </div>
                  <h1>{f.cwe_id || f.owasp_category || "Finding"}{kbName ? <span style={{ fontWeight: 500, color: "var(--ink-2)" }}> · {kbName.name}</span> : null}</h1>
                  {f.owasp_category && <div className="muted" style={{ marginBottom: 4 }}>OWASP Top 10:2025 · {owaspLabel(f.owasp_category)}</div>}
                  <div className="muted mono" style={{ wordBreak: "break-all" }}><LangBadge path={f.file_path} />{f.file_path}:{f.start_line}-{f.end_line} · {f.chunk_name}</div>
                </>
              ) : <div className="shimmer" style={{ width: 240, height: 22 }} />}
            </div>
            <div className="drawer-nav">
              <button className="small" disabled={pos <= 0} onClick={() => go(-1)} aria-label="Previous finding" title="Previous (↑ / k)">↑</button>
              <button className="small" disabled={pos < 0 || pos >= ids.length - 1} onClick={() => go(1)} aria-label="Next finding" title="Next (↓ / j)">↓</button>
              <button className="small close" onClick={onClose}>Close</button>
            </div>
          </div>
          <div className="dtabs" role="tablist">
            {tabs.map(([k, l]) => <button key={k} role="tab" aria-selected={tab === k} className={tab === k ? "on" : ""} onClick={() => setTab(k)}>{l}</button>)}
          </div>
        </div>

        <div className="dbody">
          {err && <div className="banner err" style={{ marginTop: 14 }}>{err}</div>}
          {!f ? <div className="skeleton"><span className="shimmer" /><span className="shimmer" /><span className="shimmer" /></div> : (
            <>
              {tab === "overview" && (
                <>
                  {f.status === "pending" && (
                    <div className="callout" style={{ "--c": "var(--s-pending)" }}>
                      <h4>Waiting for the LLM</h4>
                      <p>This is a retrieval candidate: the code resembles {f.cwe_id || "a known weakness"}, but nothing has been confirmed yet. This panel updates by itself when the verdict arrives. The severity shown is an estimate.</p>
                    </div>)}
                  {f.status === "unverified" && <div className="banner warn" style={{ marginTop: 14 }}>Unverified retrieval candidate. No LLM has judged this code, so it is not claimed to be a vulnerability.</div>}
                  {f.llm_vulnerable != null && (
                    <div className="callout" style={{ "--c": f.llm_vulnerable ? sevVar : "var(--sev-none)" }}>
                      <div className="verdict">
                        <span className="big">{f.llm_vulnerable ? "Vulnerable" : "Not vulnerable"}</span>
                        <span className="conf"><span className="meter"><div style={{ width: `${(f.llm_confidence || 0) * 100}%` }} /></span>{Math.round((f.llm_confidence ?? 0) * 100)}% confident</span>
                        <span className="muted" style={{ fontSize: 12 }}>{f.llm_model}</span>
                      </div>
                      <p>{f.llm_explanation}</p>
                    </div>)}
                  <h3>{f.status === "rejected" ? "Code reviewed" : "Vulnerable code"}</h3>
                  <CodeBlock code={f.code} start={f.start_line || 1} marks={f.llm_vulnerable ? hotMarks(f.code, f.llm_evidence) : null} />
                  {f.llm_evidence && <p className="muted" style={{ margin: "4px 0 0" }}>Evidence cited by the LLM: <code>{f.llm_evidence}</code></p>}
                  <h3>{f.status === "rejected" ? "Why it was rejected" : "How the severity was scored"}</h3>
                  <p style={{ margin: 0, color: "var(--ink-2)" }}>{f.rationale}</p>
                  {(f.status === "confirmed" || f.status === "needs_review" || f.status === "pending" || f.status === "unverified") && (tpl || llmFix) && (
                    <p style={{ marginTop: 16 }}><button className="primary" onClick={() => setTab("fix")}><IconWrench width={14} height={14} /> See how to fix it</button></p>)}
                </>
              )}

              {tab === "fix" && (
                <>
                  {f.status === "rejected" && <div className="banner info" style={{ marginTop: 14 }}>The LLM judged this code not vulnerable, so no fix is needed.</div>}
                  {!(tpl || llmFix) && f.status !== "rejected" && (
                    <div className="callout"><h4>{f.status === "pending" ? "Fix will appear after verification" : "No fix available yet"}</h4>
                      <p>{f.status === "pending" ? "Once the LLM confirms this finding it writes a fix for your actual code." : "There is no standard pattern for this weakness class and the LLM did not propose a fix. Open the Evidence tab to see the matched CWE entry."}</p></div>)}
                  {(tpl || llmFix) && (
                    <>
                      <div className="fixhead">
                        <div className="seg" role="group" aria-label="Fix source">
                          {llmFix && <button className={fixTab === "llm" ? "on" : ""} onClick={() => setFixTab("llm")}>Fix for this code</button>}
                          {tpl && <button className={fixTab === "template" ? "on" : ""} onClick={() => setFixTab("template")}>Standard pattern</button>}
                        </div>
                        <span className="muted" style={{ fontSize: 12 }}>Suggestions for review, never applied automatically</span>
                      </div>
                      {fixTab === "llm" && llmFix && (
                        <>
                          <div className="callout" style={{ "--c": "var(--ok)" }}><h4>What to change</h4><p>{llmFix.summary || "The LLM rewrote the vulnerable code."}</p></div>
                          {llmFix.after ? <><div className="codecap"><span>Diff (red = remove, green = add)</span></div><Diff before={llmFix.before} after={llmFix.after} /></>
                            : <div className="muted">The LLM described the fix but gave no replacement code.</div>}
                        </>
                      )}
                      {fixTab === "template" && tpl && (
                        <>
                          <div className="callout" style={{ "--c": "var(--ok)" }}><h4>{tpl.title}</h4><p>{tpl.explanation}</p></div>
                          {tpl.steps && tpl.steps.length > 0 && <><h3>Steps</h3><ol className="steps-list">{tpl.steps.map((s, i) => <li key={i}>{s}</li>)}</ol></>}
                          {tpl.note && <div className="banner info" style={{ marginTop: 14 }}><IconAlert width={14} height={14} /> {tpl.note}</div>}
                          <div className="codecap"><span>Example pattern · {LANG_NAME[tpl.language] || tpl.language}</span>
                            {tpl.languages && tpl.languages.length > 1 && <span>also in: {tpl.languages.filter((l) => l !== tpl.language).map((l) => LANG_NAME[l] || l).join(", ")}</span>}</div>
                          <Diff before={tpl.before} after={tpl.after} />
                          {tpl.reference && <p className="muted" style={{ marginTop: 8 }}>Read more: {tpl.reference}</p>}
                        </>
                      )}
                    </>
                  )}
                </>
              )}

              {tab === "evidence" && (
                <>
                  <h3>{f.llm_vulnerable != null ? "Retrieved knowledge (what the LLM was shown)" : "Retrieved knowledge (why this was flagged)"}</h3>
                  <div className="table-wrap"><table>
                    <thead><tr><th>#</th><th>Entry</th><th className="num">Fused</th><th className="num">Dense</th><th className="num">BM25</th><th className="num">Rule</th></tr></thead>
                    <tbody>{(f.retrieved_kb_context || []).map((h, i) => (
                      <tr key={h.id}><td>{i + 1}</td><td><b>{h.id}</b> <span className="muted">{h.name}</span>{h.id === f.cwe_id ? " ✓" : ""}</td>
                        <td className="num">{h.similarity?.toFixed(3)}</td><td className="num">{h.dense?.toFixed(3) ?? "-"}</td><td className="num">{h.lexical?.toFixed(2) ?? "-"}</td><td className="num">{h.pattern ? h.pattern.toFixed(2) : "-"}</td></tr>))}</tbody>
                  </table></div>
                  {f.retrieval_agrees != null && <p className="muted">The LLM's CWE {f.retrieval_agrees ? "is" : "is not"} among the top-3 retrieved entries.</p>}
                  <p><a href={`#/inspector/finding/${f.id}`}>Open in the retrieval inspector (FAISS / IDF / BM25 / rules / prompt)</a></p>
                </>
              )}

              {tab === "review" && (
                <>
                  <h3>Your decision</h3>
                  <p className="muted" style={{ marginTop: 0 }}>Record whether you agree with the finding. This is kept with the scan and appears in the exports.</p>
                  <div className="row">
                    <button className={f.triage === "accepted" ? "primary" : ""} onClick={() => triage(f.triage === "accepted" ? "" : "accepted")}><IconCheck width={14} height={14} /> Accept as real issue</button>
                    <button className={f.triage === "false_positive" ? "primary" : ""} onClick={() => triage(f.triage === "false_positive" ? "" : "false_positive")}>Mark false positive</button>
                  </div>
                  <label className="field" htmlFor="note" style={{ marginTop: 14 }}>Note</label>
                  <input id="note" type="text" placeholder="Optional note" value={note} onChange={(e) => setNote(e.target.value)} onBlur={() => f.triage && triage(f.triage)} />
                </>
              )}
            </>
          )}
        </div>
      </aside>
    </>
  );
}
