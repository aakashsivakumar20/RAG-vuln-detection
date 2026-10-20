export async function api(path, { method = "GET", body } = {}) {
  const res = await fetch("/api" + path, {
    method,
    headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON body */ }
  if (!res.ok) throw new Error((data && data.error) || `HTTP ${res.status}`);
  return data;
}

export const SEVERITIES = ["Critical", "High", "Medium", "Low"];
export const STATUS_LABEL = {
  confirmed: "Confirmed", needs_review: "Needs review", rejected: "Rejected by LLM",
  unverified: "Unverified", candidate: "Candidate", pending: "Verifying...",
};

export const LANG_BY_EXT = {
  py: "PY", js: "JS", jsx: "JS", mjs: "JS", cjs: "JS", ts: "TS", tsx: "TS", java: "Java", kt: "Kotlin", kts: "Kotlin",
  php: "PHP", phtml: "PHP", go: "Go", cs: "C#", rb: "Ruby", c: "C", h: "C", cc: "C++", cpp: "C++", cxx: "C++",
  hpp: "C++", rs: "Rust",
};
export const langOf = (path) => LANG_BY_EXT[(String(path || "").split(".").pop() || "").toLowerCase()] || "";

export const EXAMPLE_REPOS = [
  { label: "NodeGoat", url: "https://github.com/OWASP/NodeGoat", lang: "JS" },
  { label: "DVWA", url: "https://github.com/digininja/DVWA", lang: "PHP" },
  { label: "RailsGoat", url: "https://github.com/OWASP/railsgoat", lang: "Ruby" },
  { label: "WebGoat", url: "https://github.com/WebGoat/WebGoat", lang: "Java" },
  { label: "WebGoat.NET", url: "https://github.com/jerryhoff/WebGoat.NET", lang: "C#" },
  { label: "go-test-bench", url: "https://github.com/Contrast-Security-OSS/go-test-bench", lang: "Go" },
];

export const repoName = (src) => {
  const s = String(src || "").replace(/\.git$/, "").replace(/[\\/]+$/, "");
  const m = s.match(/github\.com[/:]([^/]+\/[^/]+)$/i);
  return m ? m[1] : s.replace(/^.*[\\/]/, "") || s;
};

export function fmtDuration(s) {
  if (s == null) return "-";
  if (s < 60) return `${s.toFixed(1)} s`;
  return `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`;
}

// line diff (LCS) for the before/after fix view
export function diffLines(a, b) {
  const x = (a || "").split("\n"), y = (b || "").split("\n");
  const n = x.length, m = y.length;
  if (n * m > 250000) return [...x.map((t) => ({ t: "del", s: t })), ...y.map((t) => ({ t: "add", s: t }))];
  const dp = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
  for (let i = n - 1; i >= 0; i--)
    for (let j = m - 1; j >= 0; j--)
      dp[i][j] = x[i] === y[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const out = []; let i = 0, j = 0;
  while (i < n && j < m) {
    if (x[i] === y[j]) { out.push({ t: "same", s: x[i] }); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) out.push({ t: "del", s: x[i++] });
    else out.push({ t: "add", s: y[j++] });
  }
  while (i < n) out.push({ t: "del", s: x[i++] });
  while (j < m) out.push({ t: "add", s: y[j++] });
  return out;
}

// OWASP Top 10:2025 category names (same list as the knowledge base)
export const OWASP_NAMES = {
  "A01:2025": "Broken Access Control", "A02:2025": "Security Misconfiguration", "A03:2025": "Software Supply Chain Failures",
  "A04:2025": "Cryptographic Failures", "A05:2025": "Injection", "A06:2025": "Insecure Design", "A07:2025": "Authentication Failures",
  "A08:2025": "Software or Data Integrity Failures", "A09:2025": "Security Logging and Alerting Failures",
  "A10:2025": "Mishandling of Exceptional Conditions",
};
export const owaspLabel = (c) => (OWASP_NAMES[c] ? `${c.slice(0, 3)} ${OWASP_NAMES[c]}` : c || "");
