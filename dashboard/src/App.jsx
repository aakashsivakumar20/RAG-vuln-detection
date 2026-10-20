import React, { useEffect, useState, useCallback } from "react";
import { api } from "./api.js";
import ScanPage from "./pages/ScanPage.jsx";
import ResultsPage from "./pages/ResultsPage.jsx";
import KnowledgePage from "./pages/KnowledgePage.jsx";
import EvaluationPage from "./pages/EvaluationPage.jsx";
import InspectorPage from "./pages/InspectorPage.jsx";
import SettingsPage from "./pages/SettingsPage.jsx";
import { IconShield, IconScan, IconSearch, IconBook, IconChart, IconGear, IconSun, IconMoon } from "./components/icons.jsx";

function useHash() {
  const [h, setH] = useState(window.location.hash || "#/");
  useEffect(() => {
    const f = () => setH(window.location.hash || "#/");
    window.addEventListener("hashchange", f);
    return () => window.removeEventListener("hashchange", f);
  }, []);
  return h.replace(/^#/, "") || "/";
}

function useTheme() {
  const read = () => { try { return localStorage.getItem("theme") || ""; } catch { return ""; } };
  const [theme, setTheme] = useState(read);
  useEffect(() => {
    if (theme) document.documentElement.setAttribute("data-theme", theme); else document.documentElement.removeAttribute("data-theme");
  }, [theme]);
  const systemDark = !window.matchMedia || window.matchMedia("(prefers-color-scheme: dark)").matches;
  const dark = theme ? theme === "dark" : systemDark;
  const toggle = () => { const n = dark ? "light" : "dark"; try { localStorage.setItem("theme", n); } catch { /* storage blocked */ } setTheme(n); };
  return [dark, toggle];
}

export default function App() {
  const route = useHash();
  const [dark, toggleTheme] = useTheme();
  const [health, setHealth] = useState(null);
  const [offline, setOffline] = useState(false);
  const refreshHealth = useCallback(() => {
    api("/health").then((h) => { setHealth(h); setOffline(false); }).catch(() => setOffline(true));
  }, []);
  useEffect(() => { refreshHealth(); }, [refreshHealth, route]);

  const scanMatch = route.match(/^\/scan\/(\d+)/);
  let page;
  if (scanMatch) page = <ResultsPage key={scanMatch[1]} scanId={Number(scanMatch[1])} llm={health && health.llm} />;
  else if (route.startsWith("/inspector")) { const m = route.match(/^\/inspector\/finding\/(\d+)/); page = <InspectorPage key={m ? m[1] : "free"} findingId={m ? Number(m[1]) : null} />; }
  else if (route.startsWith("/kb")) page = <KnowledgePage />;
  else if (route.startsWith("/evaluation")) page = <EvaluationPage />;
  else if (route.startsWith("/settings")) page = <SettingsPage health={health} onChange={refreshHealth} />;
  else page = <ScanPage health={health} refreshHealth={refreshHealth} />;

  const link = (to, label, Icon, active) => (
    <a href={`#${to}`} className={active ? "active" : ""} aria-current={active ? "page" : undefined}><Icon />{label}</a>
  );
  const llm = health && health.llm;
  return (
    <div className="shell">
      <nav className="nav" aria-label="Main">
        <div className="brand">
          <div className="brand-mark"><IconShield width={20} height={20} /></div>
          <div className="brand-name">Code Vulnerability Scanner<small>Dual-context RAG + LLM · v3</small></div>
        </div>
        <div className="nav-links">
          {link("/", "New scan", IconScan, route === "/" || !!scanMatch)}
          {link("/inspector", "Inspector", IconSearch, route.startsWith("/inspector"))}
          {link("/kb", "Knowledge base", IconBook, route.startsWith("/kb"))}
          {link("/evaluation", "Evaluation", IconChart, route.startsWith("/evaluation"))}
          {link("/settings", "Settings", IconGear, route.startsWith("/settings"))}
        </div>
        <div className="nav-foot">
          <div className="llm-chip">
            <span className={`led ${offline ? "" : llm && llm.configured ? "on" : "off"}`} />
            <div>
              {offline ? <b>API offline</b> : !llm ? "Checking LLM..." : llm.configured
                ? <><b>{llm.provider}</b><br />{llm.model}</>
                : <><b>No LLM key</b><br />findings stay unverified</>}
            </div>
          </div>
          <button className="theme-btn" onClick={toggleTheme} aria-label="Toggle light and dark theme">
            {dark ? <IconSun width={16} height={16} /> : <IconMoon width={16} height={16} />}{dark ? "Light theme" : "Dark theme"}
          </button>
        </div>
      </nav>
      <main className="main">
        {offline && <div className="banner err">Cannot reach the API server. Start it with <code>run.bat</code> (Windows) or <code>python -m rag_vuln_detect.api.server</code>.</div>}
        {page}
      </main>
    </div>
  );
}
