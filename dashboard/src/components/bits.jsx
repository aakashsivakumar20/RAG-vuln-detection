import React, { useEffect, useRef, useState } from "react";
import { STATUS_LABEL, langOf } from "../api.js";
import { IconCopy, IconCheck } from "./icons.jsx";

export function SevPill({ band, estimated }) {
  if (band === "None") return <span className="pill sev sev-None"><span className="dot" />Not vulnerable</span>;
  return (
    <span className={`pill sev sev-${band}${estimated ? " est" : ""}`} title={estimated ? "Estimated from retrieval only - the LLM has not judged this yet" : undefined}>
      <span className="dot" />{band}{estimated ? "?" : ""}
    </span>
  );
}

const STATUS_COLOR = { confirmed: "var(--s-confirmed)", needs_review: "var(--s-review)", rejected: "var(--s-rejected)", unverified: "var(--s-unverified)", candidate: "var(--s-unverified)", pending: "var(--s-pending)" };
export const statusColor = (s) => STATUS_COLOR[s] || "var(--muted)";

export function StatusPill({ status }) {
  if (status === "pending") return <span className="pill status-pending"><span className="spinner" />Verifying</span>;
  return <span className="pill"><span className="dot sq" style={{ background: statusColor(status) }} />{STATUS_LABEL[status] || status}</span>;
}

export function LangBadge({ path }) {
  const l = langOf(path);
  return l ? <span className="lang-badge">{l}</span> : null;
}

// stat tile; the number "bumps" when it changes so live updates are noticeable
export function Tile({ value, label, note, color }) {
  const prev = useRef(value);
  const [bump, setBump] = useState(false);
  useEffect(() => {
    if (prev.current !== value) { prev.current = value; setBump(true); const t = setTimeout(() => setBump(false), 520); return () => clearTimeout(t); }
  }, [value]);
  return (
    <div className={`tile ${color ? "accented" : ""}`} style={color ? { "--tile-c": color } : undefined} title={note || undefined}>
      <div className={`v ${bump ? "bump" : ""}`}>{value}</div><div className="l">{label}</div>{note && <div className="n">{note}</div>}
    </div>
  );
}

export function CopyButton({ text, label = "Copy" }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    try {
      if (navigator.clipboard && window.isSecureContext !== false) await navigator.clipboard.writeText(text);
      else { const ta = document.createElement("textarea"); ta.value = text; document.body.appendChild(ta); ta.select(); document.execCommand("copy"); ta.remove(); }
      setDone(true); setTimeout(() => setDone(false), 1400);
    } catch { /* clipboard blocked: nothing else to do */ }
  };
  return <button className="small copy" onClick={copy} aria-label="Copy code">{done ? <><IconCheck width={13} height={13} /> Copied</> : <><IconCopy width={13} height={13} /> {label}</>}</button>;
}

export function CodeBlock({ code, start = 1, marks, copy }) {
  const lines = (code || "").split("\n");
  return (
    <div className="codewrap">
      {copy && <CopyButton text={copy === true ? code : copy} />}
      <pre className="code" tabIndex={0}>
        {lines.map((l, i) => (
          <div key={i} className={marks ? marks[i] : ""}><span className="ln">{marks ? "" : start + i}</span>{l || " "}</div>
        ))}
      </pre>
    </div>
  );
}

// horizontal bars; one series => no legend, direct value labels
export function BarList({ items, color = "var(--accent)", empty = "Nothing to show", onPick, active }) {
  const max = Math.max(1, ...items.map((i) => i.value));
  if (!items.length) return <div className="empty">{empty}</div>;
  return (
    <div className="bars" role="list">
      {items.map((i) => (
        <div className="brow" key={i.label} role="listitem" title={i.title || `${i.label}: ${i.value}`}
          style={onPick ? { cursor: "pointer", opacity: active && active !== i.label ? .55 : 1 } : undefined} onClick={onPick ? () => onPick(i.label) : undefined}>
          <div className="bl">{i.label}</div>
          <div className="bar">{i.value > 0 && <div style={{ width: `${(i.value / max) * 100}%`, background: i.color || color }} />}</div>
          <div className="bv">{i.value}</div>
        </div>
      ))}
    </div>
  );
}

export function StackBar({ parts }) {
  const total = parts.reduce((a, p) => a + p.value, 0);
  if (!total) return <div className="empty">No results yet</div>;
  return (
    <>
      <div className="stack" role="img" aria-label={parts.map((p) => `${p.label} ${p.value}`).join(", ")}>
        {parts.filter((p) => p.value > 0).map((p) => (
          <div key={p.label} style={{ flex: p.value, background: p.color }} title={`${p.label}: ${p.value}`} />
        ))}
      </div>
      <div className="legend">
        {parts.map((p) => <span key={p.label}><span className="dot sq" style={{ background: p.color }} />{p.label} <b>{p.value}</b></span>)}
      </div>
    </>
  );
}
