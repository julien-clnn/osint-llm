import { useEffect, useMemo, useRef, useState } from "react";
import BenchmarkGraph from "../components/BenchmarkGraph.jsx";

// Same scenarios as the Analysis screen (see scenarios/*.yaml on the backend).
const SCENARIOS = [
  { value: "external_recon", label: "External recon" },
  { value: "email_security_posture", label: "Email security posture" },
  { value: "phishing_triage", label: "Phishing triage" },
];

const PROVIDER_LABELS = { deepseek: "DeepSeek", mistral: "Mistral" };

function lineTag(line) {
  if (/erreur|error/i.test(line)) return "warn";
  if (/^\[/.test(line)) return "tool";
  return "info";
}

function MetricEstimate({ label, value }) {
  return (
    <div className="metric-tile">
      <div className="metric-tile-label">{label}</div>
      <div className="metric-tile-value">{value}</div>
    </div>
  );
}

export default function Benchmark() {
  const [domains, setDomains] = useState([]);
  const [selectedDomains, setSelectedDomains] = useState([]);
  const [scenario, setScenario] = useState("external_recon");
  const [repetitions, setRepetitions] = useState(3);
  const [seed, setSeed] = useState(42);
  const [maxWorkers, setMaxWorkers] = useState(6);
  const [baseline, setBaseline] = useState(null); // most recent run, for the estimate
  const [settings, setSettings] = useState(null);
  const [providerOptions, setProviderOptions] = useState([]);
  const [provider, setProvider] = useState(""); // "" = default provider from .env
  const [phase, setPhase] = useState("form"); // form | confirm | running | done | error
  const [logLines, setLogLines] = useState([]);
  const [taskEvents, setTaskEvents] = useState([]); // per-task AgentEvent events, for BenchmarkGraph
  const [runId, setRunId] = useState(null);
  const [errorMsg, setErrorMsg] = useState("");
  const abortRef = useRef(null);
  const logRef = useRef(null);

  useEffect(() => {
    const getJson = (url) =>
      fetch(url).then(async (r) => {
        if (r.ok) return r.json();
        const body = await r.json().catch(() => null);
        throw new Error(typeof body?.detail === "string" ? body.detail : `HTTP ${r.status}`);
      });
    const showError = (err) => setErrorMsg(`Could not load benchmark data: ${err.message}`);

    getJson("/api/eval/domains")
      .then((list) => {
        if (!Array.isArray(list)) throw new Error("unexpected response");
        setDomains(list);
        setSelectedDomains(list);
      })
      .catch(showError);
    getJson("/api/eval/runs")
      .then((runs) => Array.isArray(runs) && runs.length > 0 && setBaseline(runs[0]))
      .catch(() => {});
    getJson("/api/settings")
      .then((s) => {
        setSettings(s);
        const configured = Object.entries(s.providers || {})
          .filter(([, p]) => p.configured)
          .map(([name]) => name);
        setProviderOptions(configured);
        setProvider(s.active?.provider || configured[0] || "");
      })
      .catch(() => {});
  }, []);

  useEffect(() => () => abortRef.current?.abort(), []);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logLines]);

  function toggleDomain(d) {
    setSelectedDomains((prev) => (prev.includes(d) ? prev.filter((x) => x !== d) : [...prev, d]));
  }

  // Honest estimate: based on the real averages of the last recorded run
  // (tokens/time per domain×repetition pair, with-verifier config), not on
  // made-up constants.
  const estimate = useMemo(() => {
    if (!baseline?.total_tokens_mean_with || selectedDomains.length === 0) return null;
    const nCombos = selectedDomains.length * repetitions;
    const tokens = Math.round(baseline.total_tokens_mean_with * nCombos);
    const minutes = baseline.wall_seconds_mean_with
      ? Math.max(1, Math.round((baseline.wall_seconds_mean_with * nCombos) / (60 * Math.max(1, maxWorkers))))
      : null;
    return { tokens, minutes };
  }, [baseline, selectedDomains, repetitions, maxWorkers]);

  // Launching a benchmark is a real, costly action (real LLM quota): the SSE
  // stream is read via fetch()+ReadableStream rather than EventSource, which
  // automatically reconnects after any interruption (page reload, network
  // hiccup, dev server restart). With EventSource, a reconnect after a run
  // ends silently starts a second full run as soon as the server lock is
  // released — fetch() never retries on its own.
  function handleSseChunk(raw) {
    let eventName = "message";
    let dataLine = "";
    for (const rawLine of raw.split("\n")) {
      if (rawLine.startsWith("event:")) eventName = rawLine.slice(6).trim();
      else if (rawLine.startsWith("data:")) dataLine = rawLine.slice(5).trim();
    }
    if (!dataLine) return;
    let data;
    try {
      data = JSON.parse(dataLine);
    } catch {
      return;
    }
    if (eventName === "log") {
      setLogLines((prev) => [...prev, data.line]);
    } else if (eventName === "task") {
      setTaskEvents((prev) => [...prev, data]);
    } else if (eventName === "done") {
      setRunId(data.run_id);
      setPhase("done");
    } else if (eventName === "error") {
      setErrorMsg(data.message || "Unknown error.");
      setPhase("error");
    }
  }

  async function launch() {
    setPhase("running");
    setLogLines([]);
    setTaskEvents([]);
    setErrorMsg("");
    setRunId(null);

    const params = new URLSearchParams();
    selectedDomains.forEach((d) => params.append("domains", d));
    params.set("repetitions", String(repetitions));
    params.set("seed", String(seed));
    params.set("max_workers", String(maxWorkers));
    params.set("scenario", scenario);
    if (provider) params.set("provider", provider);

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const res = await fetch(`/api/eval/launch?${params.toString()}`, { signal: controller.signal });
      if (!res.ok || !res.body) {
        throw new Error(`Server responded with ${res.status}.`);
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let sep;
        while ((sep = buffer.indexOf("\n\n")) !== -1) {
          handleSseChunk(buffer.slice(0, sep));
          buffer = buffer.slice(sep + 2);
        }
      }
    } catch (err) {
      if (controller.signal.aborted) return; // component unmounted: not a real error
      setErrorMsg(err.message || "Connection to the server failed.");
      setPhase("error");
    }
  }

  function reset() {
    setPhase("form");
    setLogLines([]);
    setTaskEvents([]);
    setRunId(null);
    setErrorMsg("");
  }

  if (phase === "confirm") {
    return (
      <>
        <div className="screen-header">
          <h1 className="screen-title">Benchmark</h1>
        </div>
        <div className="confirm-card">
          <div className="confirm-label">Launch confirmation</div>
          <h2 className="confirm-title">Launch the evaluation?</h2>
          <div className="kv-rows">
            {[
              [
                "Provider",
                provider ? `${PROVIDER_LABELS[provider] || provider} / ${settings?.providers?.[provider]?.model || "?"}` : "not configured",
              ],
              ["Scenario", SCENARIOS.find((s) => s.value === scenario)?.label],
              ["Domains", `${selectedDomains.length} selected`],
              ["Repetitions", String(repetitions)],
              ["Workers", String(maxWorkers)],
              ["Estimated tokens", estimate ? estimate.tokens.toLocaleString("en-US") : "unknown (no reference run)"],
              ["Estimated duration", estimate?.minutes ? `~${estimate.minutes} min` : "unknown"],
            ].map(([k, v]) => (
              <div key={k} className="kv-row">
                <span>{k}</span>
                <span className="mono-val">{v}</span>
              </div>
            ))}
          </div>
          {!provider || !settings?.providers?.[provider]?.configured ? (
            <p className="hint" style={{ color: "var(--red)" }}>
              No API key for this provider in <code>.env</code> — the launch will fail.
            </p>
          ) : null}
          <div className="confirm-actions">
            <button className="btn" onClick={launch}>
              Confirm launch
            </button>
            <button className="btn btn-ghost" onClick={() => setPhase("form")}>
              Cancel
            </button>
          </div>
        </div>
      </>
    );
  }

  if (phase === "running" || phase === "done" || phase === "error") {
    return (
      <>
        <div className="screen-header">
          <h1 className="screen-title">Benchmark</h1>
          <p className="screen-sub">
            {SCENARIOS.find((s) => s.value === scenario)?.label} — {selectedDomains.length} domains ×{" "}
            {repetitions} repetition{repetitions > 1 ? "s" : ""}
          </p>
        </div>

        {errorMsg ? <div className="error">{errorMsg}</div> : null}

        <BenchmarkGraph
          taskEvents={taskEvents}
          phase={phase}
          scenario={scenario}
          scenarioLabel={SCENARIOS.find((s) => s.value === scenario)?.label || scenario}
          maxWorkers={maxWorkers}
        />

        <div className="stream" style={{ marginTop: 16 }}>
          <div className="stream-head">
            <span className={`core ${phase === "running" ? "live" : "done"}`} />
            {phase === "running" ? "Benchmark running" : phase === "done" ? "Benchmark complete" : "Benchmark interrupted"}
          </div>
          <div className="stream-body" ref={logRef}>
            {logLines.map((line, i) => {
              const tag = lineTag(line);
              return (
                <div key={i} className="line">
                  <span className={`tag ${tag}`}>{tag === "warn" ? "⚠" : tag === "tool" ? "run" : "info"}</span>
                  <span className="txt">{line}</span>
                </div>
              );
            })}
          </div>
        </div>

        {phase === "done" ? (
          <p className="hint" style={{ marginTop: 16 }}>
            Run saved{runId ? (
              <>
                {" "}
                (<code>{runId}</code>)
              </>
            ) : null}{" "}
            — see the <strong style={{ color: "var(--ink)" }}>Results</strong> tab for details.
          </p>
        ) : null}

        {phase !== "running" ? (
          <div style={{ marginTop: 20 }}>
            <button className="btn" onClick={reset}>
              New benchmark
            </button>
          </div>
        ) : null}
      </>
    );
  }

  // phase === "form"
  return (
    <>
      <div className="screen-header">
        <h1 className="screen-title">Benchmark</h1>
        <p className="screen-sub">
          Configure and launch a harness evaluation (<code>evals/run_eval.py</code>) — consumes real
          quota from the provider configured in <code>.env</code>.
        </p>
      </div>

      {errorMsg ? <div className="error">{errorMsg}</div> : null}

      <div className="section">
        <h2>Domains</h2>
        <div className="chip-group">
          {domains.map((d) => (
            <button
              key={d}
              type="button"
              className={`chip ${selectedDomains.includes(d) ? "is-active" : ""}`}
              onClick={() => toggleDomain(d)}
            >
              {d}
            </button>
          ))}
        </div>
        <p className="hint">
          {selectedDomains.length} / {domains.length} selected ·{" "}
          <button type="button" className="link-btn" onClick={() => setSelectedDomains(domains)}>
            select all
          </button>{" "}
          ·{" "}
          <button type="button" className="link-btn" onClick={() => setSelectedDomains([])}>
            none
          </button>
        </p>
      </div>

      <div className="section">
        <h2>Scenario</h2>
        <div className="modes" role="radiogroup" aria-label="Scenario">
          {SCENARIOS.map((s) => (
            <button
              key={s.value}
              type="button"
              role="radio"
              aria-checked={scenario === s.value}
              className={`mode ${scenario === s.value ? "is-active" : ""}`}
              onClick={() => setScenario(s.value)}
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>

      {providerOptions.length > 1 ? (
        <div className="section">
          <h2>Provider</h2>
          <select
            className="select-input"
            aria-label="LLM provider"
            value={provider}
            onChange={(e) => setProvider(e.target.value)}
          >
            {providerOptions.map((p) => (
              <option key={p} value={p}>
                {PROVIDER_LABELS[p] || p}
              </option>
            ))}
          </select>
        </div>
      ) : null}

      <div className="section">
        <h2>Runtime parameters</h2>
        <div className="field-grid">
          <label>
            <span className="field-label">Repetitions</span>
            <input
              className="num-input"
              type="number"
              min={1}
              max={10}
              value={repetitions}
              onChange={(e) => setRepetitions(Number(e.target.value))}
            />
          </label>
          <label>
            <span className="field-label">Seed</span>
            <input className="num-input" type="number" value={seed} onChange={(e) => setSeed(Number(e.target.value))} />
          </label>
          <label>
            <span className="field-label">Max workers</span>
            <input
              className="num-input"
              type="number"
              min={1}
              max={16}
              value={maxWorkers}
              onChange={(e) => setMaxWorkers(Number(e.target.value))}
            />
          </label>
        </div>
      </div>

      <div className="section">
        <h2>Estimate (based on the last recorded run)</h2>
        {estimate ? (
          <div className="metrics-grid">
            <MetricEstimate label="Estimated tokens" value={estimate.tokens.toLocaleString("en-US")} />
            <MetricEstimate label="Estimated duration" value={estimate.minutes ? `~${estimate.minutes} min` : "—"} />
          </div>
        ) : (
          <p className="hint">
            No previous run to estimate from — launch a first run to calibrate estimates for the next ones.
          </p>
        )}
      </div>

      <button className="btn" disabled={selectedDomains.length === 0} onClick={() => setPhase("confirm")}>
        Launch evaluation →
      </button>
      {selectedDomains.length === 0 ? (
        <span className="hint" style={{ marginLeft: 12 }}>
          Select at least one domain
        </span>
      ) : null}
    </>
  );
}
