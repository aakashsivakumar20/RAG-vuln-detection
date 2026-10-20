import React, { useState } from "react";
import { api } from "../api.js";

export default function SettingsPage({ health, onChange }) {
  const [provider, setProvider] = useState("groq");
  const [key, setKey] = useState("");
  const [msg, setMsg] = useState(null);
  const [busy, setBusy] = useState(false);
  const llm = health && health.llm;

  const save = async () => {
    setBusy(true); setMsg(null);
    try { await api("/llm/key", { method: "POST", body: { provider, key } }); setKey(""); setMsg({ ok: true, t: "Key saved to the local .env file." }); onChange(); }
    catch (e) { setMsg({ ok: false, t: e.message }); }
    setBusy(false);
  };
  const test = async () => {
    setBusy(true); setMsg(null);
    try { const r = await api("/llm/test", { method: "POST", body: {} }); setMsg({ ok: true, t: `Connected: ${r.provider} / ${r.model}` }); onChange(); }
    catch (e) { setMsg({ ok: false, t: e.message }); }
    setBusy(false);
  };

  return (
    <>
      <h1>Settings</h1>
      <p className="sub">The LLM turns retrieval candidates into verdicts. Both options below have a free tier and need no credit card.</p>
      <div className="card">
        <h2>LLM connection</h2>
        <p style={{ marginTop: 0 }}>Status: {llm && llm.configured ? <b>{llm.provider} · {llm.model}</b> : <b>not configured</b>}</p>
        <div className="row" style={{ alignItems: "flex-end" }}>
          <div><label className="field" htmlFor="prov">Provider</label>
            <select id="prov" value={provider} onChange={(e) => setProvider(e.target.value)}>
              <option value="groq">Groq (console.groq.com/keys)</option>
              <option value="gemini">Google Gemini (aistudio.google.com/apikey)</option>
            </select></div>
          <div className="grow"><label className="field" htmlFor="key">API key</label>
            <input id="key" type="password" autoComplete="off" value={key} onChange={(e) => setKey(e.target.value)} placeholder="paste key here" /></div>
          <button className="primary" disabled={busy || key.length < 12} onClick={save}>Save key</button>
          <button disabled={busy || !(llm && llm.configured)} onClick={test}>Test connection</button>
        </div>
        {msg && <div className={`banner ${msg.ok ? "info" : "err"}`} style={{ marginTop: 12, marginBottom: 0 }}>{msg.t}</div>}
        <p className="muted" style={{ marginBottom: 0 }}>The key is stored only in the <code>.env</code> file next to this project on your computer and is sent only to the provider you chose.</p>
      </div>
      <div className="card">
        <h2>About</h2>
        <dl className="kv">
          <dt>Version</dt><dd>{health && health.version}</dd>
          <dt>Knowledge base</dt><dd>{health && health.kb_entries} entries (OWASP Top 10:2025, CWE Top 25:2025 + extended CWEs)</dd>
          <dt>Languages</dt><dd>Python, JavaScript, TypeScript, Java, Kotlin, PHP, Go, C#, Ruby, C / C++, Rust</dd>
          <dt>Data</dt><dd>Findings are kept in a local SQLite file (<code>data/findings.db</code>)</dd>
        </dl>
      </div>
    </>
  );
}
