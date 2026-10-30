import { useEffect, useState } from "react";
import { IS_DEMO, apiFetch } from "../lib/api.js";

const PROVIDER_LABELS = {
  deepseek: "DeepSeek",
  mistral: "Mistral",
};

function fmt(value, unit = "") {
  if (value === null || value === undefined) return "provider default";
  return `${value}${unit}`;
}

export default function Settings() {
  const [settings, setSettings] = useState(null);
  const [loadError, setLoadError] = useState("");

  useEffect(() => {
    apiFetch("/api/settings")
      .then((r) => {
        if (!r.ok) throw new Error();
        return r.json();
      })
      .then(setSettings)
      .catch(() => setLoadError("Could not read the configuration."));
  }, []);

  const active = settings?.active;
  const providers = settings?.providers || {};

  return (
    <>
      <div className="screen-header">
        <h1 className="screen-title">Settings</h1>
        <p className="screen-sub">
          Active LLM provider and model, read from the local <code>.env</code> — read-only, nothing
          is changed from the web UI.
        </p>
      </div>

      {IS_DEMO ? (
        <div className="demo-banner">
          <strong>Demo</strong> — no key is configured on this site. The values below describe the
          setup that recorded the replayed analyses.
        </div>
      ) : null}

      {loadError ? <div className="error">{loadError}</div> : null}

      {active ? (
        <>
          <div className="section">
            <h2>Active provider</h2>
            <div className="kv-rows">
              <div className="kv-row">
                <span>Provider</span>
                <span className="mono-val">{PROVIDER_LABELS[active.provider] || active.provider}</span>
              </div>
              <div className="kv-row">
                <span>Model</span>
                <span className="mono-val">{active.model || "—"}</span>
              </div>
              <div className="kv-row">
                <span>Status</span>
                <span className={`status-badge ${active.configured ? "is-ok" : "is-off"}`}>
                  {active.configured ? "configured" : "missing key"}
                </span>
              </div>
            </div>
            {!active.configured ? (
              <p className="hint" style={{ color: "var(--red)" }}>
                {active.error || "No active API key."} Set{" "}
                <code>{active.provider === "mistral" ? "MISTRAL_API_KEY" : "DEEPSEEK_API_KEY"}</code> in{" "}
                <code>.env</code>.
              </p>
            ) : null}
          </div>

          <div className="section">
            <h2>Available providers</h2>
            <div className="stream">
              <div className="stream-body" style={{ padding: 0, maxHeight: "none" }}>
                <table className="runs-table">
                  <thead>
                    <tr>
                      <th>Provider</th>
                      <th>Model</th>
                      <th>Base URL</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(providers).map(([name, p]) => (
                      <tr key={name} className={name === active.provider ? "is-selected" : ""}>
                        <td>{PROVIDER_LABELS[name] || name}</td>
                        <td>
                          <span className="mono-val">{p.model}</span>
                        </td>
                        <td>
                          <span className="mono-val">{p.base_url}</span>
                        </td>
                        <td>
                          <span className={`status-badge ${p.configured ? "is-ok" : "is-off"}`}>
                            {p.configured ? "configured" : "not configured"}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {active.configured ? (
            <div className="section">
              <h2>Active runtime parameters</h2>
              <div className="kv-rows">
                <div className="kv-row">
                  <span>Temperature</span>
                  <span className="mono-val">{fmt(active.temperature)}</span>
                </div>
                <div className="kv-row">
                  <span>Seed</span>
                  <span className="mono-val">{active.seed == null ? "random" : active.seed}</span>
                </div>
                <div className="kv-row">
                  <span>Max verification iterations</span>
                  <span className="mono-val">{active.max_verify_iterations}</span>
                </div>
                <div className="kv-row">
                  <span>Request timeout</span>
                  <span className="mono-val">{fmt(active.request_timeout, " s")}</span>
                </div>
              </div>
              <p className="hint">
                <code>OSINTLLM_TEMPERATURE</code>, <code>OSINTLLM_SEED</code>, <code>OSINTLLM_MAX_VERIFY</code>,{" "}
                <code>OSINTLLM_REQUEST_TIMEOUT</code> in <code>.env</code>.
              </p>
            </div>
          ) : null}

          <p className="hint">
            To change the provider or key, edit <code>.env</code> at the project root
            (<code>OSINTLLM_PROVIDER</code>, <code>DEEPSEEK_API_KEY</code>, <code>MISTRAL_API_KEY</code>…), then
            restart the API (<code>make api</code>).
          </p>
        </>
      ) : !loadError ? (
        <p className="hint">Loading…</p>
      ) : null}
    </>
  );
}
