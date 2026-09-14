const pptxgen = require('pptxgenjs');

// ---------- palette (same Ocean/Midnight palette as Review 2 deck) ----------
const NAVY = "21295C";
const DEEP_BLUE = "065A82";
const TEAL = "1C7293";
const ICE = "EAF3F8";
const WHITE = "FFFFFF";
const GRAY = "5B6472";
const AMBER = "C97A2B";
const RED = "B03A2E";
const GREEN = "2E8B57";

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE";
const PAGE_W = 13.33, PAGE_H = 7.5;

const FONT = "Calibri";
const FONT_HEAD = "Cambria";

function addFooter(slide, pageNum, dark) {
  slide.addText(`BCSE497J · Project I · Review 3`, {
    x: 0.5, y: PAGE_H - 0.4, w: 6, h: 0.3, fontSize: 9, color: dark ? "B9C4D6" : GRAY, fontFace: FONT, align: "left"
  });
  slide.addText(`${pageNum}`, {
    x: PAGE_W - 1, y: PAGE_H - 0.4, w: 0.5, h: 0.3, fontSize: 9, color: dark ? "B9C4D6" : GRAY, fontFace: FONT, align: "right"
  });
}

function titleBar(slide, kicker, title, dark) {
  if (kicker) {
    slide.addText(kicker.toUpperCase(), {
      x: 0.6, y: 0.35, w: 12, h: 0.35, fontSize: 12, color: dark ? "8FD3E8" : TEAL, bold: true, fontFace: FONT, charSpacing: 1
    });
  }
  slide.addText(title, {
    x: 0.6, y: kicker ? 0.68 : 0.4, w: 12.1, h: 0.9, fontSize: 28, bold: true, color: dark ? WHITE : NAVY, fontFace: FONT_HEAD
  });
}

// ================= SLIDE 1: TITLE =================
{
  const s = pres.addSlide();
  s.background = { color: NAVY };
  const nodes = [[10.6,1.2],[11.9,2.1],[10.2,2.6],[12.4,3.6],[9.6,4.1],[11.3,4.8],[10.0,5.8],[12.6,5.6]];
  nodes.forEach(([x,y],i)=>{
    nodes.forEach(([x2,y2],j)=>{
      if(j>i && Math.random()>0.55){
        s.addShape("line", {x: Math.min(x,x2), y: Math.min(y,y2), w: Math.abs(x2-x), h: Math.abs(y2-y),
          line: { color: "3A5A8C", width: 1 }, flipV: y2<y, flipH: x2<x });
      }
    });
  });
  nodes.forEach(([x,y],i)=>{
    s.addShape("ellipse", { x: x-0.09, y: y-0.09, w: 0.18, h: 0.18, fill: { color: i%3===0?TEAL:"3A5A8C" }, line: { type: "none" } });
  });

  s.addText("VIT CHENNAI  ·  SCHOOL OF COMPUTER SCIENCE AND ENGINEERING", {
    x: 0.7, y: 0.7, w: 9.5, h: 0.4, fontSize: 13, color: "8FD3E8", bold: true, fontFace: FONT, charSpacing: 1
  });
  s.addText("AI-Powered Secure Code Analysis and\nVulnerability Detection using Retrieval-\nAugmented Generation (RAG)", {
    x: 0.7, y: 1.5, w: 9.6, h: 2.6, fontSize: 34, bold: true, color: WHITE, fontFace: FONT_HEAD, lineSpacingMultiple: 1.08
  });
  s.addText("BCSE497J — Project I   |   Review 3 (Panel Review)   |   16 September 2026", {
    x: 0.7, y: 4.15, w: 9.6, h: 0.4, fontSize: 15, color: "CADCFC", fontFace: FONT
  });
  s.addShape("roundRect", { x: 0.7, y: 4.65, w: 4.5, h: 0.4, rectRadius: 0.06, fill: { color: TEAL }, line: { type: "none" } });
  s.addText("5 / 10 modules implemented · running end-to-end", {
    x: 0.7, y: 4.65, w: 4.5, h: 0.4, fontSize: 11.5, bold: true, color: WHITE, align: "center", valign: "middle", fontFace: FONT
  });

  s.addShape("rect", { x: 0.7, y: 5.25, w: 8.6, h: 0.02, fill: { color: "3A5A8C" }, line: { type: "none" } });

  s.addText([
    { text: "Presented by: ", options: { bold: true, color: "8FD3E8", breakLine: true } },
    { text: "Aakash Sivakumar — 23BCE5119", options: { color: WHITE, breakLine: true } },
    { text: "Udhay Anand Pandiyan — 23BCE1793", options: { color: WHITE } },
  ], { x: 0.7, y: 5.4, w: 9.6, h: 0.85, fontSize: 14, fontFace: FONT, lineSpacingMultiple: 1.25 });
  s.addText([
    { text: "Guide: ", options: { bold: true, color: "8FD3E8" } },
    { text: "Jenila Livingston L M", options: { color: WHITE } },
  ], { x: 0.7, y: 6.3, w: 9.6, h: 0.4, fontSize: 14, fontFace: FONT });
  s.addText("Programme: B.Tech. Computer Science and Engineering", {
    x: 0.7, y: 6.72, w: 9.6, h: 0.4, fontSize: 12, color: "9FB2CC", fontFace: FONT, italic: true
  });
}

// ================= SLIDE 2: AGENDA =================
{
  const s = pres.addSlide();
  s.background = { color: WHITE };
  titleBar(s, "Overview", "What We'll Cover");
  const items = [
    ["01", "Recap: System & Architecture", "What was designed at Review 2"],
    ["02", "Review 3 Scope", "What \"~50% implementation\" means, module by module"],
    ["03", "Implementation Walkthrough", "Ingestion → chunking → embedding → KB → retrieval"],
    ["04", "A Real Technical Decision", "The embedding-model constraint, and how we resolved it"],
    ["05", "Results Obtained So Far", "Real-repo run, labeled benchmark, automated tests"],
    ["06", "Limitations & Plan for Review 4", "What's next, and why"],
  ];
  const colW = 5.9, gap = 0.5;
  items.forEach((item, i) => {
    const col = i % 2, row = Math.floor(i / 2);
    const x = 0.6 + col * (colW + gap);
    const y = 1.7 + row * 1.55;
    s.addShape("roundRect", { x, y, w: colW, h: 1.3, rectRadius: 0.08, fill: { color: ICE }, line: { type: "none" },
      shadow: { type: "outer", color: "9FB2CC", opacity: 0.35, blur: 6, offset: 2, angle: 90 } });
    s.addText(item[0], { x: x + 0.25, y: y + 0.18, w: 1.0, h: 0.95, fontSize: 30, bold: true, color: "C7D6E8", fontFace: FONT_HEAD, align: "left", valign: "middle" });
    s.addText(item[1], { x: x + 1.15, y: y + 0.18, w: colW - 1.4, h: 0.55, fontSize: 15, bold: true, color: NAVY, fontFace: FONT, valign: "bottom" });
    s.addText(item[2], { x: x + 1.15, y: y + 0.72, w: colW - 1.4, h: 0.5, fontSize: 11.5, color: GRAY, fontFace: FONT, valign: "top" });
  });
  addFooter(s, 2);
}

// ================= SLIDE 3: RECAP - ARCHITECTURE =================
{
  const s = pres.addSlide();
  s.background = { color: WHITE };
  titleBar(s, "1 · Recap", "The Designed System (Review 2)");
  s.addImage({ path: "../design/architecture_diagram.png", x: 3.55, y: 1.35, w: 6.2, h: 5.7 });
  s.addText([
    { text: "Ten modules across five layers:\n\n", options: { bold: true, color: NAVY } },
    { text: "Input → Processing (ingest, chunk, embed) → AI/Retrieval (dual-context RAG + LLM analysis) → Scoring & Remediation → Persistence & Dashboard.\n\n", options: {} },
    { text: "Review 3 asked for roughly half of this working end-to-end against real code.", options: { bold: true, color: TEAL } },
  ], { x: 0.6, y: 1.7, w: 2.75, h: 5.2, fontSize: 11.5, color: "333F4E", fontFace: FONT, lineSpacingMultiple: 1.3, valign: "top" });
  addFooter(s, 3);
}

// ================= SLIDE 4: REVIEW 3 SCOPE (module status) =================
{
  const s = pres.addSlide();
  s.background = { color: WHITE };
  titleBar(s, "2 · Review 3 Scope", "5 of 10 Modules — Implemented and Running");

  const rows = [
    [{ text: "Module", options: { bold: true, fill: { color: DEEP_BLUE }, color: WHITE } },
     { text: "Status", options: { bold: true, fill: { color: DEEP_BLUE }, color: WHITE } },
     { text: "Evidence", options: { bold: true, fill: { color: DEEP_BLUE }, color: WHITE } }],
    [{ text: "Repository Ingestion", options: {} }, { text: "✓ Done", options: { color: GREEN, bold: true } }, { text: "Cloned & filtered a real public repo (§4.3)", options: {} }],
    [{ text: "Parsing & Chunking", options: {} }, { text: "✓ Done", options: { color: GREEN, bold: true } }, { text: "Tree-sitter, function/class-level, tested", options: {} }],
    [{ text: "Embedding Service", options: {} }, { text: "✓ Done", options: { color: GREEN, bold: true } }, { text: "Documented model substitution + measured fix (§4.2)", options: {} }],
    [{ text: "Security Knowledge Base", options: {} }, { text: "✓ Done", options: { color: GREEN, bold: true } }, { text: "35 entries: OWASP Top 10:2025 + CWE Top 25:2025", options: {} }],
    [{ text: "RAG Retrieval Orchestrator", options: {} }, { text: "✓ Done", options: { color: GREEN, bold: true } }, { text: "Dual-context retrieval demoed & benchmarked (§4.4)", options: {} }],
    [{ text: "LLM Security Analysis", options: {} }, { text: "Review 4", options: { color: AMBER, bold: true } }, { text: "Requires LLM API provisioning — planned next", options: { color: GRAY } }],
    [{ text: "Severity Scoring", options: {} }, { text: "Review 4", options: { color: AMBER, bold: true } }, { text: "Rule-based module — designed, not yet coded", options: { color: GRAY } }],
    [{ text: "Remediation Generation", options: {} }, { text: "Review 5", options: { color: GRAY, bold: true } }, { text: "Depends on LLM analysis stage", options: { color: GRAY } }],
    [{ text: "Findings Store (MongoDB)", options: {} }, { text: "Review 4", options: { color: AMBER, bold: true } }, { text: "Persistence layer for findings", options: { color: GRAY } }],
    [{ text: "Dashboard", options: {} }, { text: "Review 5", options: { color: GRAY, bold: true } }, { text: "React.js UI — final-review scope", options: { color: GRAY } }],
  ];
  s.addTable(rows, {
    x: 0.6, y: 1.6, w: 12.15, h: 5.1,
    fontSize: 10.3, fontFace: FONT, color: "333F4E",
    border: { type: "solid", color: "D8E2EC", pt: 0.75 },
    autoPage: false,
    colW: [3.4, 1.6, 7.15],
    rowH: [0.4, 0.42, 0.42, 0.42, 0.42, 0.42, 0.42, 0.42, 0.42, 0.42, 0.42],
    valign: "middle"
  });
  addFooter(s, 4);
}

// ================= SLIDE 5: IMPLEMENTATION WALKTHROUGH (pipeline w/ status) =================
{
  const s = pres.addSlide();
  s.background = { color: WHITE };
  titleBar(s, "3 · Implementation", "The Implemented Pipeline, Step by Step");

  const stages = [
    ["1", "Ingest", "Shallow git clone; filter vendored/binary/oversize/unsupported-language files", "icon_FaCode.png"],
    ["2", "Chunk", "tree-sitter AST parse → function/class-level chunks (Python, JS, TS)", "icon_FaListUl.png"],
    ["3", "Embed", "IDF-weighted GloVe averaging, camelCase/snake_case-aware tokenizer", "icon_FaBrain.png"],
    ["4", "Index KB", "OWASP Top 10:2025 + CWE Top 25:2025 → 35-entry FAISS knowledge base", "icon_FaDatabase.png"],
    ["5", "Retrieve", "Dual-context: nearest repo code + nearest security-KB entries, per chunk", "icon_FaSearch.png"],
  ];
  const n = stages.length, gap = 0.22;
  const cw = (12.15 - gap * (n - 1)) / n;
  const y = 1.85, h = 4.3;
  stages.forEach((st, i) => {
    const x = 0.6 + i * (cw + gap);
    s.addShape("roundRect", { x, y, w: cw, h, rectRadius: 0.1, fill: { color: DEEP_BLUE }, line: { type: "none" } });
    s.addImage({ path: st[3], x: x + cw/2 - 0.28, y: y + 0.25, w: 0.56, h: 0.56 });
    s.addText(st[0], { x: x + 0.15, y: y + 0.85, w: cw - 0.3, h: 0.4, fontSize: 13, bold: true, color: "8FD3E8", fontFace: FONT_HEAD, align: "center" });
    s.addText(st[1], { x: x + 0.15, y: y + 1.2, w: cw - 0.3, h: 0.45, fontSize: 15, bold: true, color: WHITE, fontFace: FONT, align: "center" });
    s.addText(st[2], { x: x + 0.18, y: y + 1.75, w: cw - 0.36, h: h - 1.95, fontSize: 9.8, color: "DCE8F5", fontFace: FONT, lineSpacingMultiple: 1.22, valign: "top", align: "center" });
    if (i < n - 1) {
      s.addText("→", { x: x + cw, y: y + h/2 - 0.25, w: gap, h: 0.5, fontSize: 16, bold: true, color: TEAL, align: "center" });
    }
  });
  s.addText("All five stages run against real code, not synthetic examples — see Results (slides 9–11).", {
    x: 0.6, y: 6.35, w: 12.1, h: 0.4, fontSize: 11, italic: true, color: GRAY, fontFace: FONT
  });
  addFooter(s, 5);
}

// ================= SLIDE 6: TECHNICAL ACCURACY - THE EMBEDDING DECISION =================
{
  const s = pres.addSlide();
  s.background = { color: WHITE };
  titleBar(s, "4 · Technical Accuracy", "A Real Constraint, and How We Resolved It");

  s.addShape("roundRect", { x: 0.6, y: 1.65, w: 12.15, h: 1.0, rectRadius: 0.08, fill: { color: "FBEDE8" }, line: { type: "none" } });
  s.addImage({ path: "icon_FaExclamationTriangle.png", x: 0.85, y: 1.85, w: 0.55, h: 0.55 });
  s.addText([
    { text: "Constraint: ", options: { bold: true, color: RED } },
    { text: "our build environment's network policy blocks Hugging Face Hub and Stanford NLP's file host — confirmed by direct connection tests — which is where the \"code-specialised embedding model\" named in our proposal is normally downloaded from.", options: { color: "333F4E" } },
  ], { x: 1.6, y: 1.72, w: 11.0, h: 0.9, fontSize: 12, fontFace: FONT, lineSpacingMultiple: 1.2, valign: "middle" });

  s.addShape("roundRect", { x: 0.6, y: 2.85, w: 12.15, h: 1.0, rectRadius: 0.08, fill: { color: ICE }, line: { type: "none" } });
  s.addImage({ path: "icon_FaCheckCircle.png", x: 0.85, y: 3.05, w: 0.55, h: 0.55 });
  s.addText([
    { text: "Resolution: ", options: { bold: true, color: GREEN } },
    { text: "GitHub-hosted distribution was reachable, so we substituted IDF-weighted averaged GloVe word vectors (glove-wiki-gigaword-100, via gensim's GitHub-hosted gensim-data) — a genuine pretrained embedding, documented everywhere it matters, confined to one module.", options: { color: "333F4E" } },
  ], { x: 1.6, y: 2.92, w: 11.0, h: 0.9, fontSize: 12, fontFace: FONT, lineSpacingMultiple: 1.2, valign: "middle" });

  s.addText("A failure we found, measured, and fixed — not just claimed to fix:", {
    x: 0.6, y: 4.15, w: 12.1, h: 0.4, fontSize: 13, bold: true, color: NAVY, fontFace: FONT
  });

  const before = ["Plain averaging retrieved CWE-22 (Path Traversal) above the correct CWE-89 (SQL Injection) on a classic SQLi snippet", "Generic shared tokens (\"select\", \"user\") diluted the average"];
  const after = ["Added IDF weighting over the KB corpus + camelCase/snake_case identifier splitting", "Re-ran the full 22-snippet benchmark to measure the actual effect, not assume it"];
  s.addShape("roundRect", { x: 0.6, y: 4.65, w: 5.9, h: 2.15, rectRadius: 0.08, fill: { color: "FBEDE8" }, line: { type: "none" } });
  s.addText("Before (plain averaging)", { x: 0.85, y: 4.8, w: 5.4, h: 0.35, fontSize: 12.5, bold: true, color: RED, fontFace: FONT });
  s.addText(before.map((t,i)=>({text:t, options:{bullet:{code:"2022"}, breakLine: i<before.length-1}})), { x: 0.85, y: 5.2, w: 5.4, h: 1.5, fontSize: 11, color: "333F4E", fontFace: FONT, lineSpacingMultiple: 1.25, paraSpaceAfter: 6, valign: "top" });

  s.addShape("roundRect", { x: 6.75, y: 4.65, w: 5.9, h: 2.15, rectRadius: 0.08, fill: { color: ICE }, line: { type: "none" } });
  s.addText("After (IDF-weighted) — 54.5% → 63.6% top-1 accuracy", { x: 7.0, y: 4.8, w: 5.4, h: 0.35, fontSize: 12.5, bold: true, color: GREEN, fontFace: FONT });
  s.addText(after.map((t,i)=>({text:t, options:{bullet:{code:"2022"}, breakLine: i<after.length-1}})), { x: 7.0, y: 5.2, w: 5.4, h: 1.5, fontSize: 11, color: "333F4E", fontFace: FONT, lineSpacingMultiple: 1.25, paraSpaceAfter: 6, valign: "top" });
  addFooter(s, 6);
}

// ================= SLIDE 7: SECURITY KNOWLEDGE BASE =================
{
  const s = pres.addSlide();
  s.background = { color: WHITE };
  titleBar(s, "3 · Implementation", "The Security Knowledge Base");

  s.addShape("roundRect", { x: 0.6, y: 1.75, w: 3.6, h: 4.65, rectRadius: 0.1, fill: { color: DEEP_BLUE }, line: { type: "none" } });
  s.addText("35", { x: 0.6, y: 2.15, w: 3.6, h: 1.0, fontSize: 50, bold: true, color: WHITE, align: "center", fontFace: FONT_HEAD });
  s.addText("standards-based entries indexed and retrievable", {
    x: 0.9, y: 3.25, w: 3.0, h: 0.8, fontSize: 12.5, color: "DCE8F5", align: "center", fontFace: FONT, lineSpacingMultiple: 1.25
  });
  s.addText("10 + 25", { x: 0.6, y: 4.4, w: 3.6, h: 0.7, fontSize: 26, bold: true, color: "8FD3E8", align: "center", fontFace: FONT_HEAD });
  s.addText("OWASP Top 10:2025 categories + CWE Top 25:2025 weaknesses", {
    x: 0.9, y: 5.05, w: 3.0, h: 0.9, fontSize: 11, color: "DCE8F5", align: "center", fontFace: FONT, lineSpacingMultiple: 1.2
  });

  const points = [
    ["icon_FaBookOpen.png", "Real, current standards", "Fetched directly from top10.owasp.org/2025 and cwe.mitre.org/top25/archive/2025 — not paraphrased from memory"],
    ["icon_FaSitemap.png", "Structured entries", "Each entry: rank, CWE-ID, name, mapped OWASP category, description, example vulnerable pattern"],
    ["icon_FaSearch.png", "Verified retrieval", "Sanity-checked on 4 classic weakness types (SQLi, command injection, path traversal, deserialization) — all correct at rank 1"],
    ["icon_FaCheckCircle.png", "Honest scope note", "The CWE→OWASP mapping is this project's own best-fit judgment, documented as such — not claimed as an official crosswalk"],
  ];
  const tx = 4.55, tw = 8.15;
  points.forEach((t, i) => {
    const ty = 1.75 + i * 1.2;
    s.addImage({ path: t[0], x: tx, y: ty + 0.05, w: 0.55, h: 0.55 });
    s.addText(t[1], { x: tx + 0.75, y: ty - 0.02, w: tw - 0.8, h: 0.4, fontSize: 14, bold: true, color: NAVY, fontFace: FONT });
    s.addText(t[2], { x: tx + 0.75, y: ty + 0.38, w: tw - 0.8, h: 0.7, fontSize: 11, color: GRAY, fontFace: FONT, lineSpacingMultiple: 1.2 });
  });
  addFooter(s, 7);
}

// ================= SLIDE 8: RESULTS - REAL REPOSITORY RUN =================
{
  const s = pres.addSlide();
  s.background = { color: WHITE };
  titleBar(s, "5 · Results So Far", "Real-Repository Run: OWASP/NodeGoat");

  s.addText("A public, intentionally-vulnerable Node.js reference application — small enough to inspect by hand, well known enough for an external sanity check.", {
    x: 0.6, y: 1.65, w: 12.1, h: 0.45, fontSize: 12, italic: true, color: GRAY, fontFace: FONT
  });
  s.addImage({ path: "../results/ingestion_funnel.png", x: 0.5, y: 2.15, w: 6.1, h: 4.6 });
  s.addImage({ path: "../results/chunking_timing.png", x: 6.75, y: 2.15, w: 6.1, h: 4.6 });
  addFooter(s, 8);
}

// ================= SLIDE 9: RESULTS - BENCHMARK ACCURACY =================
{
  const s = pres.addSlide();
  s.background = { color: WHITE };
  titleBar(s, "5 · Results So Far", "Retrieval-Accuracy Benchmark (22 Labeled Snippets)");

  s.addImage({ path: "../results/benchmark_accuracy.png", x: 0.6, y: 1.5, w: 6.5, h: 4.55 });

  s.addShape("roundRect", { x: 7.4, y: 1.5, w: 5.35, h: 2.1, rectRadius: 0.08, fill: { color: ICE }, line: { type: "none" } });
  s.addText("63.6% / 72.7%", { x: 7.65, y: 1.65, w: 4.9, h: 0.7, fontSize: 28, bold: true, color: DEEP_BLUE, fontFace: FONT_HEAD });
  s.addText("Top-1 / Top-3 retrieval accuracy against ground-truth CWE labels, using the IDF-weighted embedding actually shipped in the pipeline", {
    x: 7.65, y: 2.35, w: 4.9, h: 1.1, fontSize: 11.5, color: "333F4E", fontFace: FONT, lineSpacingMultiple: 1.25
  });

  s.addShape("roundRect", { x: 7.4, y: 3.85, w: 5.35, h: 2.2, rectRadius: 0.08, fill: { color: "FBEDE8" }, line: { type: "none" } });
  s.addText("Where it still struggles", { x: 7.65, y: 4.0, w: 4.9, h: 0.35, fontSize: 12.5, bold: true, color: RED, fontFace: FONT });
  s.addText("Closely related access-control weaknesses (Missing/Incorrect Authorization, IDOR, Broken Access Control) — these differ on facts a word-frequency model can't see (is a check present at all, or present but wrong?). This is the specific, motivated target for the Review 4 LLM reasoning step.", {
    x: 7.65, y: 4.4, w: 4.9, h: 1.55, fontSize: 10.8, color: "333F4E", fontFace: FONT, lineSpacingMultiple: 1.22
  });
  addFooter(s, 9);
}

// ================= SLIDE 10: RESULTS - TESTING =================
{
  const s = pres.addSlide();
  s.background = { color: NAVY };
  titleBar(s, "5 · Results So Far", "Automated Testing", true);

  s.addShape("roundRect", { x: 0.7, y: 1.9, w: 3.6, h: 3.6, rectRadius: 0.1, fill: { color: "1A2147" }, line: { type: "none" } });
  s.addText("7 / 7", { x: 0.7, y: 2.6, w: 3.6, h: 1.1, fontSize: 46, bold: true, color: "8FD3E8", align: "center", fontFace: FONT_HEAD });
  s.addText("automated tests passing", { x: 0.9, y: 3.7, w: 3.2, h: 0.6, fontSize: 13, color: "DCE8F5", align: "center", fontFace: FONT });
  s.addText("pytest · src/tests/test_pipeline.py", { x: 0.9, y: 4.3, w: 3.2, h: 0.5, fontSize: 10.5, italic: true, color: "9FB2CC", align: "center", fontFace: FONT });

  const tests = [
    "Python & JavaScript chunkers correctly identify function/class boundaries and names",
    "Identifier tokenizer correctly splits camelCase and snake_case",
    "Embeddings are unit-normalised (L2 norm = 1)",
    "FAISS vector store save/load round-trip preserves vectors and metadata",
    "Knowledge base loads all 35 entries correctly",
    "SQL-injection sanity check retrieves CWE-89 at rank 1",
  ];
  s.addText(tests.map((t,i)=>({text:t, options:{bullet:{code:"2713"}, color:"E4ECF7", breakLine: i<tests.length-1}})), {
    x: 4.75, y: 2.0, w: 7.9, h: 4.1, fontSize: 13, fontFace: FONT, lineSpacingMultiple: 1.35, paraSpaceAfter: 10, valign: "top"
  });
  addFooter(s, 10, true);
}

// ================= SLIDE 11: LIMITATIONS & NEXT STEPS =================
{
  const s = pres.addSlide();
  s.background = { color: WHITE };
  titleBar(s, "6 · Looking Ahead", "Limitations, Openly Stated — and the Plan for Review 4");

  const rows = [
    [{ text: "Limitation (today)", options: { bold: true, fill: { color: DEEP_BLUE }, color: WHITE } },
     { text: "Planned Review 4 Action", options: { bold: true, fill: { color: DEEP_BLUE }, color: WHITE } }],
    ["GloVe embedding is a documented substitute for a code-specialised transformer", "Swap in once model hosting/API access is available; re-run the same benchmark to measure the gain"],
    ["module.exports = function(){...} wrapper chunks as one large unit", "Split on inner method definitions for older CommonJS-style code"],
    ["Access-control CWE family (Authorization/IDOR/Access-Control) is hard to separate by retrieval alone", "Add the LLM reasoning step specifically for this weakness family"],
    ["Only Python/JS/TS processed; other languages retained, not analysed", "Extend chunking/embedding to further languages per §3.8 future scope"],
  ];
  s.addTable(rows, {
    x: 0.6, y: 1.7, w: 12.15, h: 4.6,
    fontSize: 11.5, fontFace: FONT, color: "333F4E",
    border: { type: "solid", color: "D8E2EC", pt: 0.75 },
    autoPage: false,
    colW: [6.0, 6.15],
    rowH: [0.4, 0.95, 0.95, 0.95, 0.95],
    valign: "middle"
  });
  s.addText("Review 4 (12–16 Oct 2026): integrate LLM security analysis + rule-based severity scoring end-to-end; initial dashboard.", {
    x: 0.6, y: 6.55, w: 12.1, h: 0.4, fontSize: 11, italic: true, color: GRAY, fontFace: FONT
  });
  addFooter(s, 11);
}

// ================= SLIDE 12: CLOSING =================
{
  const s = pres.addSlide();
  s.background = { color: NAVY };
  s.addImage({ path: "icon_FaShieldAlt_white.png", x: PAGE_W/2 - 0.5, y: 1.4, w: 1.0, h: 1.0 });
  s.addText("Thank You", { x: 0, y: 2.7, w: PAGE_W, h: 0.9, fontSize: 34, bold: true, color: WHITE, align: "center", fontFace: FONT_HEAD });
  s.addText("Questions & Discussion", { x: 0, y: 3.5, w: PAGE_W, h: 0.5, fontSize: 16, color: "8FD3E8", align: "center", fontFace: FONT });
  s.addText("5 of 10 modules implemented · 63.6% / 72.7% retrieval accuracy · 7 / 7 tests passing", {
    x: 0, y: 4.1, w: PAGE_W, h: 0.4, fontSize: 12.5, color: "C7D6E8", align: "center", fontFace: FONT
  });
  s.addText("AI-Powered Secure Code Analysis and Vulnerability Detection using RAG  ·  BCSE497J Project I  ·  VIT Chennai", {
    x: 0, y: 6.6, w: PAGE_W, h: 0.4, fontSize: 10.5, color: "9FB2CC", align: "center", fontFace: FONT
  });
}

pres.writeFile({ fileName: "Review3_Panel_Presentation.pptx" }).then(() => console.log("Review 3 deck written"));
