import React from "react";
import { IconCheck } from "./icons.jsx";

const STAGES = [
  ["ingestion", "Fetch"], ["chunking", "Parse"], ["embedding", "Embed"],
  ["retrieval", "Retrieve"], ["triage", "Triage"], ["analysis", "Verify"],
];

export function stageNotes(scan) {
  const c = scan.counts || {};
  const bs = scan.by_status || {};
  const total = c.chunks_analysed || Object.values(bs).reduce((a, b) => a + b, 0);
  const verified = total - (bs.pending || 0);
  return {
    ingestion: c.files_analysable != null ? `${c.files_analysable} files` : "",
    chunking: c.chunks_total != null ? `${c.chunks_total} units` : "",
    embedding: "",
    retrieval: "",
    triage: c.triage_ready_s != null ? `ready in ${c.triage_ready_s}s` : "",
    analysis: total ? `${verified}/${total}` : "",
  };
}

export function eta(scan) {
  const c = scan.counts || {};
  const bs = scan.by_status || {};
  const total = c.chunks_analysed || 0;
  const pending = bs.pending || 0;
  const verified = total - pending;
  const t0 = c.triage_ready_s;
  if (!total || verified < 3 || t0 == null || scan.elapsed_s == null) return null;
  const rate = verified / Math.max(1, scan.elapsed_s - t0);
  return Math.max(0, Math.round(pending / rate));
}

export function Stages({ scan }) {
  const idx = STAGES.findIndex(([k]) => k === scan.stage);
  const notes = stageNotes(scan);
  const done = scan.status === "done";
  const label = (k, l) => (k === "analysis" && scan.mode === "retrieval-only" ? "Finalise" : l);
  return (
    <div className="stages" role="list" aria-label="Scan stages">
      {STAGES.map(([k, l], i) => {
        const state = done || i < idx ? "done" : i === idx ? "now" : "";
        return (
          <div key={k} className={`stage ${state}`} role="listitem" aria-current={state === "now" ? "step" : undefined}>
            <div className="node">{state === "done" ? <IconCheck width={15} height={15} strokeWidth={2.6} /> : i + 1}</div>
            <div className="st-label">{label(k, l)}</div>
            <div className="st-note">{state ? notes[k] : ""}</div>
          </div>
        );
      })}
    </div>
  );
}
