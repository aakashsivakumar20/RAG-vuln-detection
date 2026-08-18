const pptxgen = require('pptxgenjs');

// ---------- palette ----------
const NAVY = "21295C";      // dark bg / primary text
const DEEP_BLUE = "065A82"; // primary
const TEAL = "1C7293";      // secondary
const ICE = "EAF3F8";       // light card bg
const WHITE = "FFFFFF";
const GRAY = "5B6472";
const AMBER = "C97A2B";
const RED = "B03A2E";
const GREEN = "2E8B57";

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE"; // 13.3 x 7.5
const PAGE_W = 13.33, PAGE_H = 7.5;

const FONT = "Calibri";
const FONT_HEAD = "Cambria";

function addFooter(slide, pageNum, dark) {
  slide.addText(`BCSE497J · Project I · Review 2`, {
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
    x: 0.6, y: kicker ? 0.68 : 0.4, w: 12.1, h: 0.9, fontSize: 30, bold: true, color: dark ? WHITE : NAVY, fontFace: FONT_HEAD
  });
}

// ================= SLIDE 1: TITLE =================
{
  const s = pres.addSlide();
  s.background = { color: NAVY };
  // decorative network motif (simple circles + lines)
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
    x: 0.7, y: 1.5, w: 9.6, h: 2.6, fontSize: 36, bold: true, color: WHITE, fontFace: FONT_HEAD, lineSpacingMultiple: 1.08
  });
  s.addText("BCSE497J — Project I   |   Review 2 (Panel Review)   |   19 August 2026", {
    x: 0.7, y: 4.25, w: 9.6, h: 0.4, fontSize: 15, color: "CADCFC", fontFace: FONT
  });

  s.addShape("rect", { x: 0.7, y: 4.95, w: 8.6, h: 0.02, fill: { color: "3A5A8C" }, line: { type: "none" } });

  s.addText([
    { text: "Presented by: ", options: { bold: true, color: "8FD3E8", breakLine: true } },
    { text: "Aakash Sivakumar — 23BCE5119", options: { color: WHITE, breakLine: true } },
    { text: "Udhay Anand Pandiyan — 23BCE1793", options: { color: WHITE } },
  ], { x: 0.7, y: 5.1, w: 9.6, h: 0.85, fontSize: 14, fontFace: FONT, lineSpacingMultiple: 1.25 });
  s.addText([
    { text: "Guide: ", options: { bold: true, color: "8FD3E8" } },
    { text: "Jenila Livingston L M", options: { color: WHITE } },
  ], { x: 0.7, y: 6.0, w: 9.6, h: 0.4, fontSize: 14, fontFace: FONT });
  s.addText("Programme: B.Tech. Computer Science and Engineering", {
    x: 0.7, y: 6.45, w: 9.6, h: 0.4, fontSize: 12, color: "9FB2CC", fontFace: FONT, italic: true
  });
}

// ================= SLIDE 2: AGENDA =================
{
  const s = pres.addSlide();
  s.background = { color: WHITE };
  titleBar(s, "Overview", "What We'll Cover");
  const items = [
    ["01", "Problem, Domain & Motivation", "Why current tools fall short"],
    ["02", "Literature Review", "20 recent papers (2024–2026) across 4 themes"],
    ["03", "Objectives & Scope", "What Project I will deliver"],
    ["04", "Proposed Methodology", "The 10-stage RAG pipeline"],
    ["05", "System Architecture & Modules", "How the pieces fit together"],
    ["06", "Feasibility, Risks & Work Plan", "Ethics, risk mitigation, review timeline"],
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

// ================= SLIDE 3: PROBLEM & MOTIVATION =================
{
  const s = pres.addSlide();
  s.background = { color: WHITE };
  titleBar(s, "1 · Domain & Problem", "Why This Matters");

  s.addText([
    { text: "As software applications grow more complex, ensuring code security has become a critical challenge.\n\n", options: { bold: false } },
    { text: "Traditional static analysis tools generate high volumes of false positives with limited, template-based explanations. Purely LLM-based reviewers hallucinate or rely on superficial patterns when ungrounded.\n\n", options: {} },
    { text: "We need a system that detects vulnerabilities, explains them against recognised standards (OWASP Top 10, CWE), scores severity defensibly, and recommends verifiable fixes.", options: { bold: true, color: NAVY } },
  ], { x: 0.6, y: 1.75, w: 6.9, h: 4.6, fontSize: 14.5, color: "333F4E", fontFace: FONT, lineSpacingMultiple: 1.25, valign: "top" });

  const stats = [
    ["76–90%+", "false-positive rate on a production SAST tool at industry scale", RED],
    ["8.2 days", "median CVSS severity-scoring delay in 2023 (up from 2.7 days in 2019)", AMBER],
    ["0.06–0.14", "pair accuracy of an ungrounded LLM distinguishing vulnerable vs. patched code", DEEP_BLUE],
  ];
  let y = 1.75;
  stats.forEach(([num, label, color]) => {
    s.addShape("roundRect", { x: 7.85, y, w: 4.9, h: 1.42, rectRadius: 0.08, fill: { color: ICE }, line: { type: "none" } });
    s.addText(num, { x: 8.1, y: y + 0.12, w: 4.4, h: 0.6, fontSize: 26, bold: true, color, fontFace: FONT_HEAD });
    s.addText(label, { x: 8.1, y: y + 0.72, w: 4.4, h: 0.6, fontSize: 11, color: GRAY, fontFace: FONT });
    y += 1.62;
  });
  s.addText("Sources: Tencent industry FP study (arXiv:2601.18844); AutoCVSS (EMNLP 2025 Industry); Vul-RAG (arXiv:2406.11147)", {
    x: 7.85, y: 6.55, w: 4.9, h: 0.5, fontSize: 8.5, italic: true, color: GRAY, fontFace: FONT
  });
  addFooter(s, 3);
}

// ================= SLIDE 4: DOMAIN LANDSCAPE (3 cards) =================
{
  const s = pres.addSlide();
  s.background = { color: WHITE };
  titleBar(s, "1 · Domain & Problem", "Three Ways to Review Code — and Why We Combine Two of Them");

  const cards = [
    { icon: "icon_FaSearch.png", title: "Static Analysis\nAlone", pts: ["Rule/signature based", "76–90%+ false positives", "No contextual explanation"], accent: RED },
    { icon: "icon_FaRobot.png", title: "LLM Alone\n(Ungrounded)", pts: ["Rich contextual reasoning", "Hallucinates root cause", "0.06–0.14 pair accuracy"], accent: AMBER },
    { icon: "icon_FaShieldAlt.png", title: "RAG-Grounded LLM\n(Proposed)", pts: ["Retrieves repo + OWASP/CWE context", "Explainable, standards-referenced", "Rule-based severity, not LLM-only"], accent: GREEN },
  ];
  const cw = 3.95, gap = 0.28, startX = 0.6, y = 1.85, h = 4.55;
  cards.forEach((c, i) => {
    const x = startX + i * (cw + gap);
    const featured = i === 2;
    s.addShape("roundRect", { x, y, w: cw, h, rectRadius: 0.1,
      fill: { color: featured ? DEEP_BLUE : ICE }, line: { type: "none" },
      shadow: featured ? { type: "outer", color: "07406B", opacity: 0.4, blur: 10, offset: 3, angle: 90 } : undefined });
    s.addImage({ path: c.icon, x: x + cw/2 - 0.4, y: y + 0.35, w: 0.8, h: 0.8 });
    s.addText(c.title, { x: x + 0.2, y: y + 1.3, w: cw - 0.4, h: 0.75, fontSize: 16, bold: true, align: "center",
      color: featured ? WHITE : NAVY, fontFace: FONT_HEAD });
    const bullets = c.pts.map((p, idx) => ({ text: p, options: { bullet: { code: "2022" }, breakLine: idx < c.pts.length - 1, color: featured ? "E4ECF7" : "333F4E" } }));
    s.addText(bullets, { x: x + 0.35, y: y + 2.25, w: cw - 0.7, h: h - 2.5, fontSize: 12, fontFace: FONT, lineSpacingMultiple: 1.3, valign: "top", paraSpaceAfter: 8 });
  });
  addFooter(s, 4);
}

// ================= SLIDE 5: OBJECTIVES & SCOPE =================
{
  const s = pres.addSlide();
  s.background = { color: WHITE };
  titleBar(s, "3 · Objectives & Scope", "What Project I Will Deliver");

  const objs = [
    "Ingest a GitHub repo & chunk code at function/class level",
    "Generate embeddings and store in a vector database",
    "Build an OWASP Top 10 + CWE knowledge base",
    "Run dual-context RAG retrieval (repo + standards)",
    "Score severity with a transparent, CVSS-inspired rule layer",
    "Generate remediation suggestions with before/after diffs",
    "Present findings on an interactive, filterable dashboard",
  ];
  s.addText("Objectives", { x: 0.6, y: 1.7, w: 7, h: 0.4, fontSize: 15, bold: true, color: TEAL, fontFace: FONT });
  const objItems = objs.map((o, i) => ({ text: o, options: { bullet: { code: "2713" }, breakLine: i < objs.length - 1, color: "333F4E" } }));
  s.addText(objItems, { x: 0.6, y: 2.15, w: 7.1, h: 4.7, fontSize: 13, fontFace: FONT, lineSpacingMultiple: 1.35, paraSpaceAfter: 9, valign: "top" });

  s.addShape("roundRect", { x: 8.05, y: 1.7, w: 4.7, h: 2.55, rectRadius: 0.08, fill: { color: ICE }, line: { type: "none" } });
  s.addText("In Scope (Project I)", { x: 8.3, y: 1.85, w: 4.2, h: 0.4, fontSize: 13, bold: true, color: GREEN, fontFace: FONT });
  s.addText("Requirement analysis · literature study · architecture & module design · tech-stack selection · KB & severity-rubric design · Python/JS prototype scope · preliminary work plan", {
    x: 8.3, y: 2.25, w: 4.2, h: 1.9, fontSize: 11.5, color: "333F4E", fontFace: FONT, lineSpacingMultiple: 1.3, valign: "top"
  });

  s.addShape("roundRect", { x: 8.05, y: 4.45, w: 4.7, h: 2.0, rectRadius: 0.08, fill: { color: ICE }, line: { type: "none" } });
  s.addText("Deferred to Project II", { x: 8.3, y: 4.6, w: 4.2, h: 0.4, fontSize: 13, bold: true, color: AMBER, fontFace: FONT });
  s.addText("Multi-language production support · CI/CD & IDE integration · PR-level scanning · historical trend & compliance reporting", {
    x: 8.3, y: 5.0, w: 4.2, h: 1.35, fontSize: 11.5, color: "333F4E", fontFace: FONT, lineSpacingMultiple: 1.3, valign: "top"
  });
  addFooter(s, 5);
}

// ================= SLIDE 6: LITERATURE LANDSCAPE =================
{
  const s = pres.addSlide();
  s.background = { color: WHITE };
  titleBar(s, "2 · Literature Review", "The Research Landscape");

  s.addShape("roundRect", { x: 0.6, y: 1.75, w: 3.6, h: 4.65, rectRadius: 0.1, fill: { color: DEEP_BLUE }, line: { type: "none" } });
  s.addText("227", { x: 0.6, y: 2.1, w: 3.6, h: 1.0, fontSize: 46, bold: true, color: WHITE, align: "center", fontFace: FONT_HEAD });
  s.addText("studies reviewed in a 2025 systematic literature review on LLM-based vulnerability detection (Jan 2020 – Jun 2025)", {
    x: 0.9, y: 3.1, w: 3.0, h: 1.3, fontSize: 12, color: "DCE8F5", align: "center", fontFace: FONT, lineSpacingMultiple: 1.25
  });
  s.addText("46.7%", { x: 0.6, y: 4.55, w: 3.6, h: 0.7, fontSize: 26, bold: true, color: "8FD3E8", align: "center", fontFace: FONT_HEAD });
  s.addText("of all studies published in 2024 alone — the field is moving fast", {
    x: 0.9, y: 5.2, w: 3.0, h: 1.0, fontSize: 11, color: "DCE8F5", align: "center", fontFace: FONT, lineSpacingMultiple: 1.2
  });

  const themes = [
    ["icon_FaBrain.png", "Detection via RAG", "Grounding LLM judgment in retrieved knowledge instead of raw pattern-matching (Vul-RAG, RepoAudit, VulnGym)"],
    ["icon_FaCheckCircle.png", "False-Positive Reduction", "Combining LLMs with static-analyzer output to cut alert fatigue (ZeroFalse, Tencent study, benchmark comparisons)"],
    ["icon_FaChartBar.png", "Severity / CVSS Scoring", "Predicting defensible severity from CVE text or code context (AutoCVSS, ML-based CVSS prioritisation)"],
    ["icon_FaCogs.png", "Automated Repair", "Generating and validating secure-code fixes, not just flags (patch-validation feedback, code-LM repair)"],
  ];
  const tx = 4.55, tw = 8.15;
  themes.forEach((t, i) => {
    const ty = 1.75 + i * 1.2;
    s.addImage({ path: t[0], x: tx, y: ty + 0.05, w: 0.55, h: 0.55 });
    s.addText(t[1], { x: tx + 0.75, y: ty - 0.02, w: tw - 0.8, h: 0.4, fontSize: 14, bold: true, color: NAVY, fontFace: FONT });
    s.addText(t[2], { x: tx + 0.75, y: ty + 0.38, w: tw - 0.8, h: 0.65, fontSize: 11, color: GRAY, fontFace: FONT, lineSpacingMultiple: 1.2 });
  });
  addFooter(s, 6);
}

// ================= SLIDE 7: KEY PAPERS TABLE =================
{
  const s = pres.addSlide();
  s.background = { color: WHITE };
  titleBar(s, "2 · Literature Review", "Key Papers (8 of 20 Reviewed)");

  const rows = [
    [{ text: "Paper", options: { bold: true, fill: { color: DEEP_BLUE }, color: WHITE } },
     { text: "Technique", options: { bold: true, fill: { color: DEEP_BLUE }, color: WHITE } },
     { text: "Key Result", options: { bold: true, fill: { color: DEEP_BLUE }, color: WHITE } }],
    ["Vul-RAG (ACM TOSEM 2025)", "Knowledge-level RAG over CVE cause/fix pairs", "+16–24% pair accuracy; found real 0-day-class bugs"],
    ["ZeroFalse (2025)", "LLM adjudication over CodeQL/SARIF + CWE rubrics", "F1 up to 0.955 on real-world data"],
    ["Tencent Industry Study (2026)", "Hybrid LLM + static analysis (LLM4PFA)", "94–98% false positives eliminated, <$0.12/alarm"],
    ["LLM vs. SAST Benchmark (2025)", "Head-to-head: GPT-4.1/Mistral/DeepSeek vs. SonarQube/CodeQL/Snyk", "LLM F1 0.75–0.80 vs. static tools 0.26–0.55"],
    ["AutoCVSS (EMNLP 2025)", "LLM CVSS-metric prediction, few-shot RAG", "Beats baselines by up to 33pp in low-resource settings"],
    ["SLR on LLM Vuln. Detection (2025)", "Meta-analysis of 227 studies", "7 recurring gaps: interpretability, deployment, eval standardisation"],
    ["RepoAudit (2025)", "Multi-agent, inter-procedural data-flow analysis", "100+ confirmed bugs found in open-source projects"],
    ["LLM Repair Case Study (ACM AIware 2024)", "Reasoning + patch-validation feedback", "Iterative feedback improves patch correctness"],
  ];
  s.addTable(rows, {
    x: 0.6, y: 1.75, w: 12.15, h: 4.9,
    fontSize: 11, fontFace: FONT, color: "333F4E",
    border: { type: "solid", color: "D8E2EC", pt: 0.75 },
    autoPage: false,
    colW: [3.6, 4.6, 3.95],
    rowH: [0.4, 0.5, 0.5, 0.5, 0.55, 0.5, 0.55, 0.5, 0.5],
    valign: "middle"
  });
  addFooter(s, 7);
}

// ================= SLIDE 8: GAP & POSITIONING =================
{
  const s = pres.addSlide();
  s.background = { color: WHITE };
  titleBar(s, "2 · Literature Review", "The Gap We Target");

  s.addText("No reviewed system combines all four of the following — this is the specific gap the proposed system addresses:", {
    x: 0.6, y: 1.7, w: 12.1, h: 0.55, fontSize: 13.5, color: "333F4E", fontFace: FONT, italic: true
  });

  const gaps = [
    ["A", "Repository-scale ingestion & chunking", "not just isolated function snippets", "icon_FaCode.png"],
    ["B", "RAG grounded in external standards", "OWASP Top 10 + CWE — not only historical CVE pairs or raw analyzer output", "icon_FaBookOpen.png"],
    ["C", "Transparent, rule-based severity", "CVSS-inspired scoring, not LLM judgment alone", "icon_FaChartBar.png"],
    ["D", "Explainable dashboard with verifiable fixes", "standards-referenced findings, developer-reviewed remediation", "icon_FaShieldAlt.png"],
  ];
  const cw = 2.95, gap = 0.18, startX = 0.6, y = 2.55, h = 3.7;
  gaps.forEach((g, i) => {
    const x = startX + i * (cw + gap);
    s.addShape("roundRect", { x, y, w: cw, h, rectRadius: 0.1, fill: { color: ICE }, line: { type: "none" } });
    s.addShape("ellipse", { x: x + cw/2 - 0.35, y: y + 0.25, w: 0.7, h: 0.7, fill: { color: DEEP_BLUE }, line: { type: "none" } });
    s.addText(g[0], { x: x + cw/2 - 0.35, y: y + 0.25, w: 0.7, h: 0.7, fontSize: 22, bold: true, color: WHITE, align: "center", valign: "middle", fontFace: FONT_HEAD });
    s.addText(g[1], { x: x + 0.2, y: y + 1.15, w: cw - 0.4, h: 0.9, fontSize: 13, bold: true, color: NAVY, fontFace: FONT, align: "center", valign: "top" });
    s.addText(g[2], { x: x + 0.2, y: y + 2.15, w: cw - 0.4, h: 1.4, fontSize: 10.5, color: GRAY, fontFace: FONT, align: "center", lineSpacingMultiple: 1.25, valign: "top" });
  });
  addFooter(s, 8);
}

// ================= SLIDE 9: METHODOLOGY PIPELINE =================
{
  const s = pres.addSlide();
  s.background = { color: WHITE };
  titleBar(s, "4 · Proposed Methodology", "The RAG-Based Detection Pipeline");

  const stages = [
    ["1", "Ingest & Chunk", "Clone repo, parse with tree-sitter, split into function/class-level chunks"],
    ["2", "Embed & Index", "Embed code chunks + OWASP/CWE docs into two vector collections"],
    ["3", "Dual-Context Retrieval", "Retrieve related repo code AND relevant security-standard entries"],
    ["4", "LLM Analysis", "CWE-aware structured prompt → verdict, mapped CWE-ID, explanation"],
    ["5", "Score & Remediate", "Rule-based CVSS-inspired severity + before/after fix suggestion"],
  ];
  const n = stages.length, gap = 0.22;
  const cw = (12.15 - gap * (n - 1)) / n;
  const y = 2.4, h = 3.4;
  stages.forEach((st, i) => {
    const x = 0.6 + i * (cw + gap);
    s.addShape("roundRect", { x, y, w: cw, h, rectRadius: 0.1, fill: { color: i === 3 ? DEEP_BLUE : ICE }, line: { type: "none" } });
    s.addText(st[0], { x: x + 0.15, y: y + 0.12, w: cw - 0.3, h: 0.55, fontSize: 22, bold: true, color: i === 3 ? "8FD3E8" : "C7D6E8", fontFace: FONT_HEAD });
    s.addText(st[1], { x: x + 0.15, y: y + 0.68, w: cw - 0.3, h: 0.75, fontSize: 12.5, bold: true, color: i === 3 ? WHITE : NAVY, fontFace: FONT, valign: "top" });
    s.addText(st[2], { x: x + 0.15, y: y + 1.5, w: cw - 0.3, h: h - 1.65, fontSize: 10, color: i === 3 ? "DCE8F5" : GRAY, fontFace: FONT, lineSpacingMultiple: 1.2, valign: "top" });
    if (i < n - 1) {
      s.addText("→", { x: x + cw, y: y + h/2 - 0.25, w: gap, h: 0.5, fontSize: 18, bold: true, color: TEAL, align: "center" });
    }
  });
  s.addText("Steps 6–10 (severity detail, dashboard) are elaborated in the supporting report, Chapter 3.", {
    x: 0.6, y: 6.1, w: 12.1, h: 0.4, fontSize: 10.5, italic: true, color: GRAY, fontFace: FONT
  });
  addFooter(s, 9);
}

// ================= SLIDE 10: SYSTEM ARCHITECTURE =================
{
  const s = pres.addSlide();
  s.background = { color: WHITE };
  titleBar(s, "5 · System Architecture", "End-to-End Architecture");
  s.addImage({ path: "../design/architecture_diagram.png", x: 3.15, y: 1.55, w: 7.0, h: 5.55 });
  addFooter(s, 10);
}

// ================= SLIDE 11: MODULE DESCRIPTION =================
{
  const s = pres.addSlide();
  s.background = { color: WHITE };
  titleBar(s, "5 · Module Design", "Module Responsibilities");

  const rows = [
    [{ text: "Module", options: { bold: true, fill: { color: DEEP_BLUE }, color: WHITE } },
     { text: "Responsibility", options: { bold: true, fill: { color: DEEP_BLUE }, color: WHITE } },
     { text: "Key Design Choice", options: { bold: true, fill: { color: DEEP_BLUE }, color: WHITE } }],
    ["Repository Ingestion", "Clone & pre-filter GitHub repo", "Shallow clone; exclude vendored/binary paths"],
    ["Parsing & Chunking", "Split source into logical units", "Tree-sitter, function/class-level (not fixed windows)"],
    ["Embedding Service", "Vectorise code & KB text", "Code-specialised model; separate repo vs. KB collections"],
    ["Security Knowledge Base", "Store OWASP/CWE as retrievable knowledge", "Built once, versioned, chunked by weakness category"],
    ["RAG Retrieval Orchestrator", "Fetch dual context per chunk", "Top-k from both repo index and KB, merged into one prompt"],
    ["LLM Security Analysis", "Classify, map to CWE, explain", "CWE-specific structured prompt/rubric"],
    ["Severity Scoring", "Assign a defensible severity band", "Rule-based, CVSS-inspired — not LLM-only"],
    ["Remediation Generation", "Suggest fix + before/after diff", "Developer-reviewed, never auto-applied"],
    ["Dashboard", "Visualise & triage findings", "Search, filter by severity/CWE/file, drill-down"],
  ];
  s.addTable(rows, {
    x: 0.6, y: 1.7, w: 12.15, h: 5.0,
    fontSize: 10.5, fontFace: FONT, color: "333F4E",
    border: { type: "solid", color: "D8E2EC", pt: 0.75 },
    autoPage: false,
    colW: [2.9, 4.6, 4.65],
    valign: "middle"
  });
  addFooter(s, 11);
}

// ================= SLIDE 12: TECH STACK =================
{
  const s = pres.addSlide();
  s.background = { color: WHITE };
  titleBar(s, "5 · Implementation", "Technology Stack");

  const stack = [
    ["icon_FaCode.png", "Frontend", "React.js, HTML, CSS, JavaScript"],
    ["icon_FaCogs.png", "Backend", "Node.js, Express.js"],
    ["icon_FaDatabase.png", "Database", "MongoDB (scans, findings, users)"],
    ["icon_FaSitemap.png", "Vector Store", "FAISS · ChromaDB · Pinecone"],
    ["icon_FaBrain.png", "AI Components", "LLM · code-specialised embeddings · RAG orchestration"],
    ["icon_FaShieldAlt.png", "Security Standards", "OWASP Top 10 · CWE · CVSS-inspired scoring"],
  ];
  const cols = 3, cw = 3.95, ch = 2.15, gapx = 0.18, gapy = 0.3, startX = 0.6, startY = 1.85;
  stack.forEach((it, i) => {
    const col = i % cols, row = Math.floor(i / cols);
    const x = startX + col * (cw + gapx), y = startY + row * (ch + gapy);
    s.addShape("roundRect", { x, y, w: cw, h: ch, rectRadius: 0.09, fill: { color: ICE }, line: { type: "none" } });
    s.addImage({ path: it[0], x: x + 0.25, y: y + 0.25, w: 0.55, h: 0.55 });
    s.addText(it[1], { x: x + 0.95, y: y + 0.22, w: cw - 1.15, h: 0.6, fontSize: 14, bold: true, color: NAVY, fontFace: FONT, valign: "middle" });
    s.addText(it[2], { x: x + 0.25, y: y + 0.95, w: cw - 0.5, h: ch - 1.1, fontSize: 11, color: GRAY, fontFace: FONT, lineSpacingMultiple: 1.25, valign: "top" });
  });
  addFooter(s, 12);
}

// ================= SLIDE 13: INNOVATION =================
{
  const s = pres.addSlide();
  s.background = { color: NAVY };
  titleBar(s, "Distinguishing Factor", "Innovation", true);

  s.addImage({ path: "icon_FaLightbulb.png", x: 0.7, y: 2.0, w: 1.6, h: 1.6 });
  s.addText([
    { text: "Two independent knowledge sources, one transparent scorer.\n\n", options: { bold: true, fontSize: 20, color: WHITE } },
    { text: "RAG grounded simultaneously in the target repository's own code (context) and an external, standards-based security corpus — OWASP Top 10 + CWE (grounding) — paired with a ", options: { fontSize: 14.5, color: "DCE8F5" } },
    { text: "rule-based, CVSS-inspired severity layer", options: { fontSize: 14.5, bold: true, color: "8FD3E8" } },
    { text: " that does not depend solely on LLM judgment.", options: { fontSize: 14.5, color: "DCE8F5" } },
  ], { x: 2.6, y: 2.05, w: 10.0, h: 2.6, fontFace: FONT, lineSpacingMultiple: 1.3, valign: "top" });

  s.addText([
    { text: "Motivated directly by two literature findings:  ", options: { bold: true, color: "8FD3E8" } },
    { text: "Vul-RAG shows knowledge-level RAG substantially outperforms ungrounded LLM judgment; AutoCVSS shows pure-LLM severity scoring is not consistently reliable versus rule-assisted approaches.", options: { color: "C7D6E8" } },
  ], { x: 2.6, y: 4.9, w: 10.0, h: 1.5, fontSize: 12.5, fontFace: FONT, lineSpacingMultiple: 1.3, valign: "top" });
  addFooter(s, 13, true);
}

// ================= SLIDE 14: FEASIBILITY, RISKS, ETHICS =================
{
  const s = pres.addSlide();
  s.background = { color: WHITE };
  titleBar(s, "6 · Feasibility & Risk", "Feasibility, Risks & Ethics");

  const rows = [
    [{ text: "Risk", options: { bold: true, fill: { color: DEEP_BLUE }, color: WHITE } },
     { text: "Impact", options: { bold: true, fill: { color: DEEP_BLUE }, color: WHITE } },
     { text: "Mitigation", options: { bold: true, fill: { color: DEEP_BLUE }, color: WHITE } }],
    ["LLM hallucinated/superficial findings", "False findings undermine trust", "Mandatory RAG grounding in OWASP/CWE KB; confidence shown"],
    ["Residual false positives", "Alert fatigue", "CWE-specific structured prompting; severity module deprioritises low-confidence findings"],
    ["Large repos exceed time/cost budget", "Poor UX, high LLM cost", "Chunk-level batching, embedding cache, configurable filters"],
    ["Auto-generated fixes applied blindly", "Could introduce new bugs", "Fixes always shown as a diff for manual developer review"],
    ["Analysing code without consent", "Ethical/legal concern", "Public-repo scope only; explicit user submission required"],
  ];
  s.addTable(rows, {
    x: 0.6, y: 1.7, w: 12.15, h: 3.35,
    fontSize: 11, fontFace: FONT, color: "333F4E",
    border: { type: "solid", color: "D8E2EC", pt: 0.75 },
    autoPage: false,
    colW: [3.6, 3.6, 4.95],
    valign: "middle"
  });
  s.addText("Feasibility: every core technique (chunking, embedding retrieval, LLM classification) is individually validated at scale in the reviewed literature — the main risk is integration, not novelty.", {
    x: 0.6, y: 5.3, w: 12.15, h: 0.6, fontSize: 11.5, italic: true, color: GRAY, fontFace: FONT
  });
  addFooter(s, 14);
}

// ================= SLIDE 15: WORK PLAN / TIMELINE =================
{
  const s = pres.addSlide();
  s.background = { color: WHITE };
  titleBar(s, "6 · Work Planning", "Work Plan Aligned to the Review Schedule");

  const milestones = [
    ["Review 2", "19 Aug 2026", "Domain, literature, architecture & module design", true],
    ["Review 3", "16 Sep 2026", "Ingestion + chunking + embedding pipeline; KB built; ~50% modules working", false],
    ["Draft Report / Review 4", "12–16 Oct 2026", "RAG + LLM analysis + severity scoring integrated end-to-end; initial dashboard", false],
    ["Review 5 (Final)", "21 Oct 2026", "Remediation generation, dashboard polish, testing, final report & demo", false],
  ];
  const n = milestones.length, startX = 1.4, endX = 11.9, y = 3.3;
  const stepX = (endX - startX) / (n - 1);
  const clampX = (centerX, w) => Math.max(0.4, Math.min(centerX - w / 2, PAGE_W - 0.4 - w));
  s.addShape("line", { x: startX, y, w: endX - startX, h: 0, line: { color: "C7D6E8", width: 2 } });
  milestones.forEach((m, i) => {
    const x = startX + i * stepX;
    s.addShape("ellipse", { x: x - 0.14, y: y - 0.14, w: 0.28, h: 0.28, fill: { color: m[3] ? TEAL : DEEP_BLUE }, line: { color: WHITE, width: 2 } });
    const above = i % 2 === 0;
    const boxY = above ? y - 1.75 : y + 0.35;
    const wLabel = 2.6, wDesc = 2.8;
    s.addText(m[0], { x: clampX(x, wLabel), y: boxY, w: wLabel, h: 0.35, fontSize: 13, bold: true, color: NAVY, align: "center", fontFace: FONT });
    s.addText(m[1], { x: clampX(x, wLabel), y: boxY + 0.32, w: wLabel, h: 0.3, fontSize: 10.5, color: TEAL, align: "center", fontFace: FONT, bold: true });
    s.addText(m[2], { x: clampX(x, wDesc), y: boxY + 0.62, w: wDesc, h: 0.95, fontSize: 9.5, color: GRAY, align: "center", fontFace: FONT, lineSpacingMultiple: 1.15 });
  });
  addFooter(s, 15);
}

// ================= SLIDE 16: CLOSING =================
{
  const s = pres.addSlide();
  s.background = { color: NAVY };
  s.addImage({ path: "icon_FaShieldAlt_white.png", x: PAGE_W/2 - 0.5, y: 1.5, w: 1.0, h: 1.0 });
  s.addText("Thank You", { x: 0, y: 2.8, w: PAGE_W, h: 0.9, fontSize: 34, bold: true, color: WHITE, align: "center", fontFace: FONT_HEAD });
  s.addText("Questions & Discussion", { x: 0, y: 3.6, w: PAGE_W, h: 0.5, fontSize: 16, color: "8FD3E8", align: "center", fontFace: FONT });
  s.addText("AI-Powered Secure Code Analysis and Vulnerability Detection using RAG  ·  BCSE497J Project I  ·  VIT Chennai", {
    x: 0, y: 6.6, w: PAGE_W, h: 0.4, fontSize: 10.5, color: "9FB2CC", align: "center", fontFace: FONT
  });
}

pres.writeFile({ fileName: "Review2_Panel_Presentation.pptx" }).then(() => console.log("full deck written"));
