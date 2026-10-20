import React, { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";

const EXAMPLES = {
  "SQL built by concatenation (Python)": ["python", `def find_user(cur, name):\n    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")\n    return cur.fetchall()`],
  "Command injection (Python)": ["python", `import os\n\ndef ping(host):\n    return os.system("ping -c 1 " + host)`],
  "innerHTML with user data (JS)": ["javascript", `function show(params) {\n  document.getElementById("out").innerHTML = "<p>" + params.get("msg") + "</p>";\n}`],
  "Unsafe deserialization (Python)": ["python", `import pickle\n\ndef load(request):\n    return pickle.loads(request.data)`],
  "Hard-coded secret (JS)": ["javascript", `const jwt = require("jsonwebtoken");\nconst token = jwt.sign({ id: 1 }, "supersecret123");`],
};

const LANGS = ["python", "javascript", "typescript"];
const f3 = (x) => (x == null ? "-" : Number(x).toFixed(3));

function Bar({ v, max, color }) {
  return <span className="meter wide"><div style={{ width: `${Math.min(100, (v / (max || 1)) * 100)}%`, background: color || "var(--accent)" }} /></span>;
}

function Slider({ label, hint, value, min, max, step, onChange, def }) {
  return (
    <label className="slider">
      <span><b>{label}</b> <span className="muted">{hint}</span></span>
      <span className="row" style={{ gap: 8 }}>
        <input type="range" min={min} max={max} step={step} value={value} onChange={(e) => onChange(Number(e.target.value))} />
        <b style={{ minWidth: 38, textAlign: "right" }}>{value.toFixed(2)}</b>
        {Math.abs(value - def) > 1e-9 && <button className="linkish" onClick={() => onChange(def)}>reset ({def})</button>}
      </span>
    </label>
  );
}

export default function InspectorPage({ findingId }) {
  const [code, setCode] = useState(EXAMPLES["SQL built by concatenation (Python)"][1]);
  const [lang, setLang] = useState("python");
  const [data, setData] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [alpha, setAlpha] = useState(0.5);
  const [beta, setBeta] = useState(1.0);
  const [usePrior, setUsePrior] = useState(true);
  const [sel, setSel] = useState(null);
  const [showPrompt, setShowPrompt] = useState(false);

  const adopt = (d) => {
    setData(d); setAlpha(d.defaults.alpha); setBeta(d.defaults.beta); setSel(d.candidates[0] ? d.candidates[0].id : null);
  };
  const run = () => {
    setBusy(true); setErr("");
    api("/inspect", { method: "POST", body: { code, language: lang } })
      .then(adopt).catch((e) => setErr(e.message)).finally(() => setBusy(false));
  };
  useEffect(() => {
    if (!findingId) return;
    setBusy(true); setErr("");
    api(`/findings/${findingId}/inspect`).then((d) => { adopt(d); setLang(d.language || "python"); })
      .catch((e) => setErr(e.message)).finally(() => setBusy(false));
  }, [findingId]);
  useEffect(() => { if (!findingId) run(); /* first load */ }, []); // eslint-disable-line

  // recompute fused score client-side from the returned components so the sliders respond instantly
  const rows = useMemo(() => {
    if (!data) return [];
    const pb = data.prior_bonus || 0;
    const r = data.candidates.map((c) => {
      const prior = usePrior ? c.prior : 0;
      const dense = alpha * c.dense_norm, lex = (1 - alpha) * c.bm25_norm, rule = beta * c.pattern;
      return { ...c, p_dense: dense, p_lex: lex, p_rule: rule, p_prior: prior, total: dense + lex + rule + prior };
    });
    r.sort((a, b) => b.total - a.total);
    return r.map((c, i) => ({ ...c, now: i + 1 }));
  }, [data, alpha, beta, usePrior]);
  const maxTotal = Math.max(0.01, ...rows.map((r) => r.total));
  const top = rows[0];
  const second = rows[1];
  const detail = rows.find((r) => r.id === sel) || top;
  const maxShare = data ? Math.max(0.001, ...data.tokens.map((t) => t.share)) : 1;
  const maxIdf = data ? Math.max(0.001, ...data.lexical_tokens.map((t) => t.idf)) : 1;

  return (
    <>
      <h1>Retrieval inspector</h1>
      <p className="sub">
        See exactly how a code unit is matched to the knowledge base: how the embedder weighs each word (IDF), what FAISS returns,
        what BM25 adds, which static rules fire, how the three signals are fused, and the prompt the LLM finally receives.
        This runs the same code the scanner uses. {findingId && <b>Showing the code unit of finding #{findingId}.</b>}
      </p>

      <div className="card">
        <div className="row" style={{ marginBottom: 8 }}>
          <label className="row" style={{ gap: 6 }}>Language
            <select value={lang} onChange={(e) => setLang(e.target.value)} disabled={!!findingId}>{LANGS.map((l) => <option key={l}>{l}</option>)}</select></label>
          {!findingId && (
            <label className="row" style={{ gap: 6 }}>Example
              <select value="" onChange={(e) => { const ex = EXAMPLES[e.target.value]; if (ex) { setLang(ex[0]); setCode(ex[1]); } }}>
                <option value="">choose...</option>{Object.keys(EXAMPLES).map((k) => <option key={k}>{k}</option>)}</select></label>)}
          {!findingId && <button className="primary" onClick={run} disabled={busy || !code.trim()}>{busy ? "Analysing..." : "Inspect"}</button>}
          {findingId && <a href="#/inspector" className="linkish">Inspect your own code instead</a>}
        </div>
        {!findingId && <textarea value={code} onChange={(e) => setCode(e.target.value)} rows={8} spellCheck={false} className="codearea" aria-label="Code to inspect" />}
        {findingId && data && <pre className="code" style={{ maxHeight: 220, overflow: "auto" }}>{data.code}</pre>}
        {err && <div className="banner err" style={{ marginTop: 10 }}>{err}</div>}
      </div>

      {data && <>
        <div className="card">
          <h2>1. Fusion: how the final ranking is built</h2>
          <p className="muted" style={{ marginTop: 0 }}>
            score = <b>alpha</b> x dense(FAISS, normalised) + (1 - alpha) x BM25(normalised) + <b>beta</b> x static-rule score + prior. Move the sliders to see the ranking change
            (computed live from the numbers below). Defaults are the values fitted on the dev set.
          </p>
          <div className="sliders">
            <Slider label="alpha" hint="dense vs keyword" value={alpha} min={0} max={1} step={0.05} onChange={setAlpha} def={data.defaults.alpha} />
            <Slider label="beta" hint="weight of rule hits" value={beta} min={0} max={3} step={0.25} onChange={setBeta} def={data.defaults.beta} />
            <label className="row" style={{ gap: 6 }}><input type="checkbox" checked={usePrior} onChange={(e) => setUsePrior(e.target.checked)} /> base-rate prior (+{data.prior_bonus} for OWASP / Top-25)</label>
          </div>
          <div className="legend" style={{ margin: "10px 0 6px" }}>
            <span><span className="dot sq" style={{ background: "#2a78d6" }} />dense (FAISS)</span>
            <span><span className="dot sq" style={{ background: "#eb6834" }} />BM25 keywords</span>
            <span><span className="dot sq" style={{ background: "#006300" }} />static rules</span>
            <span><span className="dot sq" style={{ background: "#898781" }} />prior</span>
          </div>
          <div className="table-wrap"><table>
            <thead><tr><th>#</th><th>KB entry</th><th>Fused score (stacked)</th><th>Dense cos</th><th>BM25</th><th>Rule</th><th title="rank if only that signal were used">Rank by dense / BM25</th></tr></thead>
            <tbody>
              {rows.slice(0, 15).map((r) => (
                <tr key={r.id} className={r.id === detail.id ? "sel" : ""} onClick={() => setSel(r.id)} style={{ cursor: "pointer" }}>
                  <td>{r.now}</td>
                  <td><b>{r.id}</b> <span className="muted">{r.name}</span></td>
                  <td style={{ minWidth: 200 }}>
                    <div className="stack thin" title={`dense ${f3(r.p_dense)} + bm25 ${f3(r.p_lex)} + rules ${f3(r.p_rule)} + prior ${f3(r.p_prior)}`}>
                      <div style={{ width: `${(r.p_dense / maxTotal) * 100}%`, background: "#2a78d6" }} />
                      <div style={{ width: `${(r.p_lex / maxTotal) * 100}%`, background: "#eb6834" }} />
                      <div style={{ width: `${(r.p_rule / maxTotal) * 100}%`, background: "#006300" }} />
                      <div style={{ width: `${(r.p_prior / maxTotal) * 100}%`, background: "#898781" }} />
                    </div>
                    <span className="muted">{f3(r.total)}</span>
                  </td>
                  <td>{f3(r.dense)}<div className="muted">norm {f3(r.dense_norm)}</div></td>
                  <td>{r.bm25.toFixed(2)}<div className="muted">norm {f3(r.bm25_norm)}</div></td>
                  <td>{r.pattern ? <b>{f3(r.pattern)}</b> : <span className="muted">-</span>}</td>
                  <td className="muted">{r.rank_dense} / {r.rank_bm25}</td>
                </tr>))}
            </tbody>
          </table></div>
          {top && second && <p className="muted" style={{ marginBottom: 0 }}>
            Margin between #1 and #2: <b>{f3(top.total - second.total)}</b>. The scanner flags a finding as low-confidence when this margin is below 0.15.
            Dense cosine values cluster in a narrow band (that is why raw cosine alone is a weak ranker); the normalised columns are what fusion uses.
          </p>}
        </div>

        <div className="card">
          <h2>2. Why {detail.id}? <span className="muted" style={{ fontWeight: 400 }}>{detail.name}</span></h2>
          <div className="chart-grid">
            <div>
              <h3>Shared BM25 words (weighted by IDF)</h3>
              {detail.matched_tokens.length === 0 ? <div className="muted">No identifier of this code occurs in the entry's text or its keyword signals.</div> :
                detail.matched_tokens.map((t) => (
                  <div className="brow2" key={t.token}><code>{t.token}</code><Bar v={t.idf} max={maxIdf} color="#eb6834" /><span className="muted">idf {t.idf}</span></div>))}
            </div>
            <div>
              <h3>Static rules for this CWE</h3>
              {data.rule_hits.filter((h) => h.cwe === detail.id).length === 0 ? <div className="muted">No rule fired for this CWE.</div> :
                data.rule_hits.filter((h) => h.cwe === detail.id).map((h, i) => (
                  <div key={i} className="rulehit"><b>{h.rule}</b> <span className="muted">weight {h.weight} · line {h.line}</span><br /><code>{h.text}</code><br /><span className="muted">{h.note}</span></div>))}
              <h3>Ranks</h3>
              <div className="muted">Dense-only: #{detail.rank_dense} · BM25-only: #{detail.rank_bm25} · after fusion with current sliders: <b>#{detail.now}</b></div>
            </div>
          </div>
        </div>

        <div className="card">
          <h2>3. All static rules that fired</h2>
          {data.rule_hits.length === 0 ? <div className="muted">None of the {data.rules_loaded} rules matched this code, so ranking relies on dense + BM25 only.</div> : (
            <div className="table-wrap"><table>
              <thead><tr><th>Rule</th><th>CWE</th><th>Weight</th><th>Line</th><th>Matched text</th><th>Meaning</th></tr></thead>
              <tbody>{data.rule_hits.map((h, i) => (
                <tr key={i}><td><b>{h.rule}</b></td><td>{h.cwe}</td><td>{h.weight}</td><td>{h.line}</td><td><code>{h.text}</code></td><td className="muted">{h.note}</td></tr>))}</tbody>
            </table></div>)}
          <p className="muted" style={{ marginBottom: 0 }}>Several rules for one CWE combine as 1 - (1-w1)(1-w2)...; so extra weak evidence adds a little, never more than 1. Rules ignore whole-line comments.</p>
        </div>

        <div className="chart-grid">
          <div className="card">
            <h2>4. Embedder: how words are weighted</h2>
            <p className="muted" style={{ marginTop: 0 }}>The dense vector is the IDF-weighted mean of GloVe word vectors. Share = the fraction of the vector this word contributes. Words not in GloVe contribute nothing.</p>
            <div className="table-wrap" style={{ maxHeight: 360, overflowY: "auto" }}><table>
              <thead><tr><th>Token</th><th>x</th><th>IDF</th><th>Share of vector</th></tr></thead>
              <tbody>{data.tokens.slice(0, 40).map((t) => (
                <tr key={t.token} className={t.in_vocab ? "" : "dim"}>
                  <td><code>{t.token}</code>{!t.in_vocab && <span className="muted"> not in GloVe</span>}</td><td>{t.count}</td><td>{t.in_vocab ? t.idf : "-"}</td>
                  <td><Bar v={t.share} max={maxShare} /> {(t.share * 100).toFixed(1)}%</td></tr>))}</tbody>
            </table></div>
          </div>
          <div className="card">
            <h2>5. BM25: which words searched the KB</h2>
            <p className="muted" style={{ marginTop: 0 }}>Identifier tokens (camelCase and snake_case split, keywords removed). IDF is high for words found in few KB entries. "KB docs" is how many entries contain the word.</p>
            <div className="table-wrap" style={{ maxHeight: 360, overflowY: "auto" }}><table>
              <thead><tr><th>Token</th><th>IDF</th><th>KB docs</th><th>In entries</th></tr></thead>
              <tbody>{data.lexical_tokens.filter((t) => t.kb_docs > 0).slice(0, 40).map((t) => (
                <tr key={t.token}><td><code>{t.token}</code></td><td>{t.idf}</td><td>{t.kb_docs}</td><td className="muted">{t.matches.join(", ")}{t.kb_docs > t.matches.length ? " ..." : ""}</td></tr>))}</tbody>
            </table></div>
            <p className="muted" style={{ marginBottom: 0 }}>{data.lexical_tokens.filter((t) => t.kb_docs === 0).length} further tokens occur in no KB entry and are ignored.</p>
          </div>
        </div>

        {data.finding && (
          <div className="card">
            <h2>6. What this scan actually stored for finding #{data.finding.id}</h2>
            <p className="muted" style={{ marginTop: 0 }}>The knowledge entries shown to the LLM at scan time (read from the database), for comparison with the live recomputation above.</p>
            <div className="table-wrap"><table>
              <thead><tr><th>#</th><th>Entry</th><th>Fused</th><th>Dense</th><th>BM25</th><th>Rule</th></tr></thead>
              <tbody>{(data.finding.stored_kb_context || []).map((h, i) => (
                <tr key={i}><td>{i + 1}</td><td><b>{h.id}</b> <span className="muted">{h.name}</span></td><td>{f3(h.similarity)}</td><td>{f3(h.dense)}</td><td>{h.lexical == null ? "-" : Number(h.lexical).toFixed(2)}</td><td>{h.pattern == null ? "-" : f3(h.pattern)}</td></tr>))}</tbody>
            </table></div>
          </div>)}

        <div className="card">
          <div className="row" style={{ justifyContent: "space-between" }}>
            <h2 style={{ margin: 0 }}>{data.finding ? "7" : "6"}. The exact prompt sent to the LLM</h2>
            <button onClick={() => setShowPrompt(!showPrompt)}>{showPrompt ? "Hide" : "Show"} prompt</button>
          </div>
          <p className="muted">Top {data.prompt.kb_top_k} entries by the default fusion, each with its rubric ("vulnerable when" / "safe when"). The model must answer in a fixed JSON format and judge only the code chunk.</p>
          {showPrompt && <>
            <h3>System</h3><pre className="code wrap">{data.prompt.system}</pre>
            <h3>User</h3><pre className="code wrap">{data.prompt.user}</pre></>}
        </div>
      </>}
    </>
  );
}
