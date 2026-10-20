import React, { useEffect, useState } from "react";
import { api } from "../api.js";

const pct = (x) => (x == null ? "-" : `${(x * 100).toFixed(1)}%`);
const SERIES = [["dev", "Development (tuned here)", "#9aa5b1"], ["heldout", "Held-out (seen once)", "var(--s-review)"],
  ["extended", "Extended CWEs (seen once)", "var(--s-unverified)"], ["heldout2", "Fresh blind set (Python/JS)", "var(--s-confirmed)"], ["langs", "Other languages", "#2e9e6b"]];

function GroupedBars({ configs, sets, metric }) {
  const act = SERIES.filter(([k]) => sets[k]);
  const W = 640, rowH = 16 * act.length + 16, left = 250, h = configs.length * rowH + 30;
  const x = (v) => left + v * (W - left - 44);
  return (
    <svg viewBox={`0 0 ${W} ${h}`} width="100%" style={{ maxWidth: 700 }} role="img" aria-label={`${metric} by retrieval method and evaluation set`}>
      {[0, .25, .5, .75, 1].map((t) => (
        <g key={t}><line x1={x(t)} x2={x(t)} y1={0} y2={h - 22} stroke="var(--grid)" />
          <text x={x(t)} y={h - 6} fontSize="11" fill="var(--muted)" textAnchor="middle">{t * 100}%</text></g>
      ))}
      {configs.map((c, i) => (
        <g key={c}>
          <text x={left - 8} y={i * rowH + 4 + 8 * act.length + 4} fontSize="12" fill="var(--ink-2)" textAnchor="end">{c.length > 42 ? c.slice(0, 41) + "…" : c}</text>
          {act.map(([k, label, col], j) => {
            const v = sets[k].configs[c]?.[metric] ?? 0, y = i * rowH + 4 + j * 16;
            return (<g key={k}>
              <rect x={left} y={y} width={Math.max(2, x(v) - left)} height={13} rx={3} fill={col}><title>{label}: {pct(v)}</title></rect>
              <text x={x(v) + 5} y={y + 10.5} fontSize="11" fill="var(--ink)">{pct(v)}</text></g>);
          })}
        </g>))}
    </svg>
  );
}

const COLS = [["top1", "Top-1"], ["top3", "Top-3"], ["top5", "Top-5"], ["top6", "Top-6"], ["top10", "Top-10"],
  ["family_top1", "Near-miss top-1"], ["mrr", "MRR", (v) => (v == null ? "-" : v.toFixed(3))]];

function MetricTable({ configs, cols }) {
  return (
    <div className="table-wrap"><table>
      <thead><tr><th>Method</th>{cols.map(([k, l]) => <th key={k} className="num">{l}</th>)}</tr></thead>
      <tbody>{Object.entries(configs).map(([name, m]) => (
        <tr key={name}><td>{name}</td>{cols.map(([k, , fmt]) => <td key={k} className="num">{fmt ? fmt(m[k]) : pct(m[k])}</td>)}</tr>))}</tbody>
    </table></div>
  );
}

export default function EvaluationPage() {
  const [ev, setEv] = useState(null);
  useEffect(() => { api("/evaluation").then(setEv); }, []);
  if (!ev) return <div className="muted">Loading...</div>;
  const r = ev.retrieval, l = ev.llm;
  const names = r ? Object.keys(r.sets.dev.configs) : [];
  return (
    <>
      <h1>Evaluation</h1>
      <p className="sub">Measured results saved by the evaluation scripts in <code>evaluation/</code>. Nothing here is typed in by hand.</p>

      <div className="card">
        <h2>Retrieval: does the right CWE come back?</h2>
        {!r ? <div className="empty">Run <code>python evaluation/run_retrieval_report.py</code></div> : (
          <>
            <p style={{ marginTop: 0 }}>
              Knowledge base: {ev.kb_entries || 269} entries. Methods are shown from plain dense search up to the final retriever
              (dense + BM25 + project-authored keyword signals + static "dangerous API" rules + a small base-rate prior).
              Fusion weights were chosen on the <b>development</b> set only (α = {r.alpha}). The <b>fresh blind set</b> ({r.sets.heldout2 ? r.sets.heldout2.n : 0} snippets)
              was written after the rules were frozen and is the fairest number; the held-out and extended sets were looked at once while the rules were being written,
              so treat them as optimistic.
            </p>
            <GroupedBars configs={names} sets={r.sets} metric="top1" />
            <div className="legend" style={{ margin: "6px 0 14px" }}>
              {SERIES.filter(([k]) => r.sets[k]).map(([k, label, col]) => <span key={k}><span className="dot sq" style={{ background: col }} />{label} · n={r.sets[k].n}</span>)}
            </div>
            <div className="banner info">All snippets were written by the project team, and the sink rules by the same people, so real-world accuracy on unfamiliar repositories will be lower than these figures.
              "Hybrid + signals (v1 retriever)" is the retriever of the first release, shown so the gain from the new rules is visible.</div>
            {r.sets.langs && (<>
              <h3>Other languages (Java, PHP, Go, C#, Ruby, C, Rust, Kotlin), all metrics</h3>
              <p className="muted" style={{ marginTop: 0 }}>67 vulnerable/patched pairs written after the per-language rules. Two rule gaps found on the first run (PHP string concatenation, Ruby <code>permit!</code>) were fixed afterwards, so the first-run figures are saved separately in <code>results/langs_first_run.json</code>. C++ shares the C rules and is not benchmarked separately.</p>
              <MetricTable configs={r.sets.langs.configs} cols={COLS} />
              {r.langs_by_language && (<div className="table-wrap"><table>
                <thead><tr><th>Language (final retriever)</th><th className="num">Pairs</th><th className="num">Top-1</th><th className="num">Top-3</th><th className="num">Top-6</th></tr></thead>
                <tbody>{Object.entries(r.langs_by_language).map(([lang, m]) => (
                  <tr key={lang}><td>{lang}</td><td className="num">{m.n}</td><td className="num">{pct(m.top1)}</td><td className="num">{pct(m.top3)}</td><td className="num">{pct(m.top6)}</td></tr>))}</tbody>
              </table></div>)}
            </>)}
            {r.sets.heldout2 && (<><h3>Fresh blind set, all metrics</h3><MetricTable configs={r.sets.heldout2.configs} cols={COLS} /></>)}
            <h3>Held-out set (Top-25 CWEs)</h3>
            <MetricTable configs={r.sets.heldout.configs} cols={COLS} />
            {r.sets.extended && (<><h3>Extended-CWE set</h3><MetricTable configs={r.sets.extended.configs} cols={COLS} /></>)}
            <h3>Development set</h3>
            <MetricTable configs={r.sets.dev.configs} cols={COLS} />
            <p className="muted">Top-6 is what the LLM is shown in a scan. "Near-miss" counts a closely related CWE (project-defined families, e.g. CWE-77 / CWE-78) as correct. Exact match is strict: a sibling CWE counts as a miss.</p>
          </>
        )}
      </div>

      <div className="card">
        <h2>LLM verdicts: does retrieval help the LLM?</h2>
        {!l ? (
          <div className="empty">Not run yet. With an API key configured, run <code>python evaluation/run_llm_benchmark.py</code>; results appear here.</div>
        ) : (
          <>
            <p style={{ marginTop: 0 }}>Model <b>{l.provider}/{l.model}</b> on {l.n_pairs} vulnerable/patched code pairs ({l.n_pairs * 2} snippets), run {l.generated_at}. Each pair counts as correct only if the vulnerable version is flagged <i>and</i> the patched version is not.</p>
            <MetricTable configs={l.configs} cols={[["pair_accuracy", "Pair accuracy"], ["accuracy", "Accuracy"], ["vuln_recall", "Vuln. recall"], ["false_positive_rate", "False-positive rate"], ["cwe_accuracy", "CWE correct"]]} />
            {l.by_split && (<>
              <h3>Pair accuracy by split</h3>
              <div className="table-wrap"><table>
                <thead><tr><th>Configuration</th><th className="num">Development</th><th className="num">Held-out (Top-25)</th><th className="num">Extended CWEs</th><th className="num">Fresh blind set</th><th className="num">Other languages</th></tr></thead>
                <tbody>{Object.entries(l.by_split).map(([cfg, sp]) => (
                  <tr key={cfg}><td>{cfg}</td>{["dev", "heldout", "extended", "heldout2", "langs"].map((k) => <td key={k} className="num">{sp[k] && sp[k].n_pairs ? `${pct(sp[k].pair_accuracy)} (n=${sp[k].n_pairs})` : "-"}</td>)}</tr>))}</tbody>
              </table></div>
            </>)}
            {l.notes && <p className="muted">{l.notes}</p>}
          </>
        )}
      </div>
    </>
  );
}
