import { useEffect, useRef, useState } from "react";
import ActivityStream from "../components/ActivityStream.jsx";
import AgentGraph from "../components/AgentGraph.jsx";
import ReportView from "../components/ReportView.jsx";
import { IS_DEMO, apiFetch, loadDemoIndex } from "../lib/api.js";

// SSE events the agent can emit to feed the live log.
const STREAM_EVENTS = [
  "info",
  "assistant_message",
  "tool_call",
  "tool_result",
  "verification",
];

// Available scenarios (see scenarios/*.yaml on the backend) — hardcoded here
// rather than fetched from a dedicated endpoint, since the list is small and fixed.
const SCENARIOS = [
  { value: "external_recon", label: "External recon" },
  { value: "email_security_posture", label: "Email security posture" },
  { value: "phishing_triage", label: "Phishing triage" },
];

const PROVIDER_LABELS = { deepseek: "DeepSeek", mistral: "Mistral" };

export default function Analysis() {
  const [domain, setDomain] = useState("");
  const [mode, setMode] = useState("passive"); // passive | active
  const [scenario, setScenario] = useState("external_recon");
  const [useProxy, setUseProxy] = useState(false); // via Tor/proxy (active mode)
  const [useCache, setUseCache] = useState(true);
  const [providerOptions, setProviderOptions] = useState([]);
  const [provider, setProvider] = useState(""); // "" = default provider from .env
  const [status, setStatus] = useState("idle"); // idle | running | done | error
  const [events, setEvents] = useState([]);
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");
  const abortRef = useRef(null);
  const settledRef = useRef(false); // true as soon as a final report is received
  const [demoIndex, setDemoIndex] = useState([]); // recorded analyses (demo build only)

  // Demo build: the domain field becomes a picker over the recorded analyses
  // of the current scenario (see lib/api.js).
  useEffect(() => {
    if (IS_DEMO) loadDemoIndex().then(setDemoIndex).catch(() => {});
  }, []);
  const demoDomains = demoIndex.filter((e) => e.scenario === scenario);
  useEffect(() => {
    if (!IS_DEMO) return;
    if (!demoDomains.some((e) => e.domain === domain)) setDomain(demoDomains[0]?.domain || "");
  }, [demoIndex, scenario]); // eslint-disable-line react-hooks/exhaustive-deps

  // One-off provider choice for this analysis (never touches .env) — the
  // selector is only shown when more than one provider has a key.
  useEffect(() => {
    apiFetch("/api/settings")
      .then((r) => r.json())
      .then((s) => {
        const configured = Object.entries(s.providers || {})
          .filter(([, p]) => p.configured)
          .map(([name]) => name);
        setProviderOptions(configured);
        setProvider(s.active?.provider || configured[0] || "");
      })
      .catch(() => {});
  }, []);

  // Cleanly abort the stream if the component unmounts mid-analysis.
  useEffect(() => () => abortRef.current?.abort(), []);

  // Read via fetch()+ReadableStream rather than EventSource: EventSource
  // automatically reconnects after any stream interruption (including a
  // normal end, due to a race between receiving the last event and the
  // network close), which would re-run a whole analysis — i.e. a duplicate
  // real LLM call — without confirmation. fetch() never retries on its own.
  function handleSseChunk(raw) {
    let eventName = "message";
    let dataLine = "";
    for (const rawLine of raw.split("\n")) {
      if (rawLine.startsWith("event:")) eventName = rawLine.slice(6).trim();
      else if (rawLine.startsWith("data:")) dataLine = rawLine.slice(5).trim();
    }
    if (!dataLine) return; // comment/keepalive lines (": ...") are ignored
    let data;
    try {
      data = JSON.parse(dataLine);
    } catch {
      return;
    }

    if (STREAM_EVENTS.includes(eventName)) {
      setEvents((prev) => [...prev, { type: eventName, data }]);
      return;
    }
    if (eventName === "report") {
      settledRef.current = true;
      setReport(data);
      setStatus("done");
      return;
    }
    if (eventName === "error" && !settledRef.current) {
      setError(data.message || "Connection to the server failed.");
      setStatus("error");
    }
  }

  async function start() {
    const d = domain.trim();
    if (!d || status === "running") return;

    abortRef.current?.abort();
    settledRef.current = false;
    setStatus("running");
    setEvents([]);
    setReport(null);
    setError("");

    const proxy = mode === "active" && useProxy;
    const url = `/api/analyze?domain=${encodeURIComponent(d)}&cache=${useCache}&mode=${mode}&proxy=${proxy}&scenario=${scenario}${provider ? `&provider=${provider}` : ""}`;

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const res = await apiFetch(url, { signal: controller.signal });
      if (!res.ok || !res.body) {
        const body = await res.json().catch(() => null);
        throw new Error(
          typeof body?.detail === "string"
            ? body.detail
            : "Connection to the server failed.",
        );
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
      if (controller.signal.aborted || settledRef.current) return;
      setError(err.message || "Connection to the server failed.");
      setStatus("error");
    }
  }

  function onKeyDown(e) {
    if (e.key === "Enter") start();
  }

  const busy = status === "running";

  return (
    <>
      <header>
        <p className="eyebrow">
          <span aria-hidden="true">🛰️</span> osintllm · passive &amp; active domain reconnaissance
        </p>
        <h1>
          An OSINT agent driven by an <span className="accent">LLM</span>
        </h1>
        <p className="lede">
          From a single domain name, the agent orchestrates public third-party sources
          (WHOIS, Certificate Transparency, IP geolocation) and produces a structured risk
          report, relying almost exclusively on third parties rather than the target itself.
        </p>
      </header>

      {IS_DEMO ? (
        <div className="demo-banner">
          <strong>Demo</strong> — no LLM is connected here. Each analysis is the replay of a real
          run recorded with the local setup{demoDomains[0]?.recorded_at ? ` (${demoDomains[0].recorded_at.slice(0, 10)})` : ""},
          streamed at {"\u2248"}3× speed. Pick one of the recorded domains below.
        </div>
      ) : null}

      <div className="form">
        <div className="form-top">
          {IS_DEMO ? (
            <label className="field">
              <span className="prompt">$</span>
              <select
                className="demo-select"
                aria-label="Recorded domain"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                disabled={busy}
              >
                {demoDomains.map((e) => (
                  <option key={e.domain} value={e.domain}>
                    {e.domain}
                  </option>
                ))}
              </select>
            </label>
          ) : (
          <label className="field">
            <span className="prompt">$</span>
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyDown={onKeyDown}
              placeholder="example.com"
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="none"
              spellCheck="false"
              data-lpignore="true"
              data-1p-ignore=""
              data-form-type="other"
              disabled={busy}
            />
          </label>
          )}
          <button className="btn" onClick={start} disabled={busy || !domain.trim()}>
            {busy ? "Analyzing…" : "Analyze"}
          </button>
        </div>
        <div className="form-controls">
          <div className="modes" role="radiogroup" aria-label="Scenario">
            {SCENARIOS.map((s) => (
              <button
                key={s.value}
                type="button"
                role="radio"
                aria-checked={scenario === s.value}
                className={`mode ${scenario === s.value ? "is-active" : ""}`}
                onClick={() => setScenario(s.value)}
                disabled={busy || (IS_DEMO && !demoIndex.some((e) => e.scenario === s.value))}
              >
                {s.label}
              </button>
            ))}
          </div>
          <div className="modes" role="radiogroup" aria-label="Reconnaissance mode">
            <button
              type="button"
              role="radio"
              aria-checked={mode === "passive"}
              className={`mode ${mode === "passive" ? "is-active" : ""}`}
              onClick={() => setMode("passive")}
              disabled={busy}
            >
              Passive
            </button>
            <button
              type="button"
              role="radio"
              aria-checked={mode === "active"}
              className={`mode ${mode === "active" ? "is-active" : ""}`}
              onClick={() => setMode("active")}
              disabled={busy || IS_DEMO}
            >
              Active
            </button>
          </div>
          {!IS_DEMO && providerOptions.length > 1 ? (
            <select
              className="select-input"
              aria-label="LLM provider"
              value={provider}
              onChange={(e) => setProvider(e.target.value)}
              disabled={busy}
            >
              {providerOptions.map((p) => (
                <option key={p} value={p}>
                  {PROVIDER_LABELS[p] || p}
                </option>
              ))}
            </select>
          ) : null}
        </div>
        {/* Dedicated checkbox row: its own line, below the selectors, so
            that "Via Tor / proxy" appearing in active mode never shifts the
            rest of the form. The always-present checkbox (cache) comes first
            at a fixed position; the conditional one (proxy) is appended
            after it without moving anything. */}
        <div className="form-checks">
          {IS_DEMO ? null : (
          <label className="check">
            <input
              type="checkbox"
              checked={useCache}
              onChange={(e) => setUseCache(e.target.checked)}
              disabled={busy}
            />
            Use cache
          </label>
          )}
          {mode === "active" ? (
            <label className="check">
              <input
                type="checkbox"
                checked={useProxy}
                onChange={(e) => setUseProxy(e.target.checked)}
                disabled={busy}
              />
              Via Tor / proxy
            </label>
          ) : null}
        </div>
      </div>

      <p className="mode-hint">
        {mode === "passive" ? (
          <>
            <strong>Passive reconnaissance</strong> — public third-party
            sources only, no direct contact with the analyzed domain.
          </>
        ) : (
          <>
            <strong>Active reconnaissance</strong> — adds one lightweight HTTP
            request to the target (header fingerprinting) on top of the
            third-party sources.
            {useProxy ? (
              <>
                {" "}
                Routed <strong>via Tor / a proxy</strong>: the target sees the
                exit node's IP, not yours (requires a running proxy, e.g. a
                local Tor daemon).
              </>
            ) : (
              <>
                {" "}
                This request goes to the target <strong>from your IP</strong>;
                check "Via Tor / proxy" to route it differently.
              </>
            )}
          </>
        )}
      </p>

      {error ? <div className="error">{error}</div> : null}

      {events.length > 0 || busy ? (
        <>
          <AgentGraph
            events={events}
            status={status}
            mode={mode}
            scenario={scenario}
            scenarioLabel={SCENARIOS.find((s) => s.value === scenario)?.label || scenario}
          />
          <ActivityStream events={events} status={status} />
        </>
      ) : null}

      {report ? <ReportView report={report} /> : null}
    </>
  );
}
