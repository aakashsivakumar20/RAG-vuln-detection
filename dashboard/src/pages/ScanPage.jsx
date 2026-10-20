import React, { useEffect, useRef, useState } from "react";
import { api, fmtDuration, repoName, EXAMPLE_REPOS } from "../api.js";
import { IconLink, IconLayers, IconBolt, IconBrain, IconWrench, IconSearch } from "../components/icons.jsx";

const HOW = [
  { Icon: IconLayers, n: "1", t: "Parse", d: "Clones the repo and splits every file into functions and classes with tree-sitter (12 languages)." },
  { Icon: IconSearch, n: "2", t: "Retrieve", d: "Matches each unit against 260+ OWASP / CWE entries (FAISS + BM25 + sink rules) and against the rest of the repo." },
  { Icon: IconBrain, n: "3", t: "Judge", d: "An LLM reads the code with both contexts and decides: vulnerable or not, how sure, and why." },
  { Icon: IconWrench, n: "4", t: "Fix", d: "Each confirmed issue gets a severity score, a fix for your actual code and a standard secure pattern." },
];

export default function ScanPage({ health, refreshHealth }) {
  const [source, setSource] = useState("");
  const [budget, setBudget] = useState(40);
  const [useRag, setUseRag] = useState(true);
  const [skipTests, setSkipTests] = useState(true);
  const [replay, setReplay] = useState(false);
  const [err, setErr] = useState("");
  const [scans, setScans] = useState([]);
  const [active, setActive] = useState(null);
  const [busy, setBusy] = useState(false);
  const timer = useRef(null);

  const load = async () => {
    try {
      const r = await api("/scans");
      setScans(r.scans);
      setActive(r.scans.find((s) => s.status === "running") || null);
    } catch (e) { /* offline banner handles it */ }
  };
  useEffect(() => { load(); timer.current = setInterval(load, 2000); return () => clearInterval(timer.current); }, []);

  const start = async (src) => {
    setErr(""); setBusy(true);
    try {
      const r = await api("/scans", { method: "POST", body: { source: src, max_llm_chunks: Number(budget), use_rag: useRag, skip_tests: skipTests, llm_mode: replay ? "replay" : "auto" } });
      refreshHealth();
      window.location.hash = `#/scan/${r.scan_id}`;       // the results page is the live view
    } catch (e) { setErr(e.message); }
    setBusy(false);
  };

  const llm = health && health.llm;
  const cached = health && health.llm_cache_entries;
  return (
    <>
      <section className="hero">
        <h1>Find the vulnerable code in any repository</h1>
        <p className="sub">Paste a GitHub link. Candidates appear in seconds, the LLM then verifies each one while you watch, and every confirmed issue comes with a severity score and a fix.</p>
        <form className="urlbar" onSubmit={(e) => { e.preventDefault(); source.trim() && start(source.trim()); }}>
          <IconLink width={20} height={20} />
          <input id="src" className="grow" type="text" value={source} aria-label="Repository URL, folder path or zip file" autoFocus
            placeholder="https://github.com/OWASP/NodeGoat   or   C:\projects\myapp" onChange={(e) => setSource(e.target.value)} />
          <button type="submit" className="primary" disabled={busy || !source.trim()}>Scan</button>
        </form>
        <div className="chips">
          <span className="lead">Try one:</span>
          {EXAMPLE_REPOS.map((r) => (
            <button key={r.url} className="chip" disabled={busy} onClick={() => { setSource(r.url); start(r.url); }} title={r.url}>{r.label}<span className="lang">{r.lang}</span></button>
          ))}
          <span className="lead" style={{ marginLeft: 8 }}>Bundled:</span>
          <button className="chip" disabled={busy} onClick={() => start("demo")} title="Intentionally vulnerable Python / JavaScript app shipped with this project">Demo app<span className="lang">PY JS</span></button>
          <button className="chip" disabled={busy} onClick={() => start("demo-languages")} title="One vulnerable file each in Java, Kotlin, PHP, Go, C#, Ruby, C and Rust">Multi-language demo<span className="lang">8 langs</span></button>
        </div>
        {err && <div className="banner err" style={{ marginTop: 14, marginBottom: 0 }}>{err}</div>}
        <details className="opts">
          <summary>Scan options</summary>
          <div className="optgrid">
            <div>
              <label className="field" htmlFor="budget">LLM budget: verify the {budget} most suspicious code units</label>
              <input id="budget" type="range" min="5" max="200" step="5" value={budget} onChange={(e) => setBudget(e.target.value)} />
              <div className="muted" style={{ fontSize: 12 }}>
                Free tiers allow roughly 10-30 requests per minute, so 40 units take a few minutes. Candidates are listed immediately either way.
                {cached != null && <> {cached} verdicts are cached; scanning the same code again replays them in seconds.</>}
              </div>
            </div>
            <div>
              <label style={{ display: "block", marginBottom: 6 }}><input type="checkbox" checked={useRag} onChange={(e) => setUseRag(e.target.checked)} /> Give the LLM retrieved OWASP / CWE context (RAG)</label>
              <label style={{ display: "block", marginBottom: 6 }}><input type="checkbox" checked={skipTests} onChange={(e) => setSkipTests(e.target.checked)} /> Skip test files</label>
              <label style={{ display: "block" }} title="Never calls the LLM: units without a cached verdict are listed as unverified. For offline demos.">
                <input type="checkbox" checked={replay} onChange={(e) => setReplay(e.target.checked)} /> Offline replay (cached verdicts only, no API calls)</label>
            </div>
          </div>
        </details>
      </section>

      {llm && !llm.configured && (
        <div className="banner warn">
          No LLM key is set, so scans will list <b>unverified</b> retrieval candidates only (not confirmed vulnerabilities).{" "}
          <a href="#/settings">Add a free Groq or Gemini key</a> to get verdicts, severity from LLM confidence and fixes for your code.
        </div>
      )}
      {active && (
        <div className="banner info">Scan #{active.id} ({repoName(active.repo_url)}) is running. <a href={`#/scan/${active.id}`}>Watch it live</a></div>
      )}

      <div className="pipeline" aria-label="How it works">
        {HOW.map(({ Icon, n, t, d }) => (
          <div className="pstep" key={n}><div className="ic"><Icon width={18} height={18} /></div><div className="pn">Step {n}</div><h3>{t}</h3><p>{d}</p></div>
        ))}
      </div>

      <div className="card">
        <h2>Recent scans</h2>
        {scans.length === 0 ? <div className="empty">No scans yet. Click one of the examples above.</div> : (
          <div className="scan-list">
            {scans.slice(0, 8).map((s) => {
              const bs = s.by_status || {};
              const Mini = ({ v, c, l }) => <span className={v ? "" : "z"} style={{ "--c": c }} title={l}>{v}</span>;
              return (
                <div key={s.id} className="scan-item" role="link" tabIndex={0} onClick={() => (window.location.hash = `#/scan/${s.id}`)}
                  onKeyDown={(e) => e.key === "Enter" && (window.location.hash = `#/scan/${s.id}`)}>
                  <div className="sid">#{s.id}</div>
                  <div style={{ minWidth: 0 }}>
                    <div className="nm" title={s.repo_url}>{repoName(s.repo_url)}</div>
                    <div className="sm">{s.status === "running" ? "running now" : s.status} · {s.mode}{s.model ? ` · ${s.provider}/${s.model}` : ""}</div>
                  </div>
                  <div className="mini" aria-label="confirmed, needs review, rejected, unverified">
                    <Mini v={bs.confirmed || 0} c="var(--s-confirmed)" l="Confirmed" /><Mini v={bs.needs_review || 0} c="var(--s-review)" l="Needs review" />
                    <Mini v={bs.rejected || 0} c="var(--s-rejected)" l="Rejected" /><Mini v={(bs.unverified || 0) + (bs.pending || 0)} c="var(--s-unverified)" l="Unverified" />
                  </div>
                  <div className="tm muted num">{fmtDuration(s.timings && s.timings.total_s)}</div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </>
  );
}
