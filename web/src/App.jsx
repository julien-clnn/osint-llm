import { useState } from "react";
import Analysis from "./screens/Analysis.jsx";
import Benchmark from "./screens/Benchmark.jsx";
import Results from "./screens/Results.jsx";
import Settings from "./screens/Settings.jsx";

const TABS = [
  { id: "analyse", label: "Analysis" },
  { id: "benchmark", label: "Benchmark" },
  { id: "resultats", label: "Results" },
  { id: "reglages", label: "Settings" },
];

export default function App() {
  const [tab, setTab] = useState("analyse");

  return (
    <div className="wrap">
      <nav className="topnav">
        <span className="topnav-brand">OSINT//AGENT</span>
        <div className="modes" role="tablist" aria-label="Section">
          {TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              role="tab"
              aria-selected={tab === t.id}
              className={`mode ${tab === t.id ? "is-active" : ""}`}
              onClick={() => setTab(t.id)}
            >
              {t.label}
            </button>
          ))}
        </div>
      </nav>

      {tab === "analyse" ? <Analysis /> : null}
      {tab === "benchmark" ? <Benchmark /> : null}
      {tab === "resultats" ? <Results /> : null}
      {tab === "reglages" ? <Settings /> : null}
    </div>
  );
}
