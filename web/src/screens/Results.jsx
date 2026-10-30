import { useEffect, useState } from "react";
import { apiFetch } from "../lib/api.js";

function pct(x, digits = 1) {
  return x == null ? "—" : `${(x * 100).toFixed(digits)}%`;
}

function num(x, digits = 1) {
  return x == null ? "—" : x.toFixed(digits);
}

// Per-metric explanations — sourced from docs/EVAL_PLAN.md and the harness
// docstrings (evals/harness/{metrics,entities,injector,judge}.py).
// Shown on hover/focus of the matching tile (see MetricTile).
const METRIC_INFO = {
  hallucination_hard:
    "Share of factual entities cited in the free text (IPs, ASNs, dates, subdomains) that are absent from every tool observation of the run — the only source of truth. Mean and standard deviation are computed over all domains and repetitions of this configuration (not just over the repetitions of a single domain).",
  completion:
    "Share of runs that finished cleanly via submit_report (with or without verifier correction), rather than looping until max_iterations or drifting into free text.",
  precision:
    "Share of reported subdomains that belong to the ground truth's known sample or known exclusions. Does not cover domains with a very large surface, where the ground truth is deliberately partial.",
  recall:
    "Share of the known subdomain sample (ground truth) actually found in the report. Measures the agent's faithfulness to the collected data — not the completeness of the collection itself.",
  tokens:
    "Tokens consumed (sum over LLM calls) to produce one report, with-verifier config. On some large-context domains the standard deviation exceeds the mean — one or two outliers, not uniform behavior.",
  latency:
    "Wall-clock time, from the first LLM call to submit_report, with-verifier config.",
  false_positive:
    "Rate at which the verifier fires (verified=False) on an UNALTERED report — measured on only 8 domains, not all 15. Without this number the per-family detection rate means nothing: a verifier that rejects everything would score 100% detection AND 100% false positives.",
  judge_hallucination_soft:
    "Share of the report's natural-language claims judged unsupported or contradicted by an LLM-as-judge (always deepseek-reasoner, fixed regardless of the evaluated provider) that only sees the run's tool observations. Complements the hard layer on non-literal wording. Measured once per domain — the judge is fallible, see the README.",
  judge_assertions:
    "Share of the ground truth's must_contain / must_not_contain assertions judged correctly reflected in the report, by the same fixed judge. Measured once per domain, not on every repetition.",
};

// Description of each injected error family — the injector's exact
// behavior, see evals/harness/injector.py.
const FAMILY_INFO = {
  fake_ip_or_asn:
    "A fake IP (TEST-NET-3 range, RFC 5737, never routable) and an ASN outside any plausible public range are added to the risk justification. Measures whether the verifier detects an entity absent from the tool observations.",
  invented_subdomain:
    "A plausible subdomain never observed by the tools (e.g. admin-portal-1234.<domain>) is added to the summary. Measures whether the verifier detects a hallucinated subdomain.",
  contradicted_risk:
    "The risk level is forced to 'high' with an entirely fabricated malicious VirusTotal reputation justification that contradicts the collected facts. Measures whether the verifier detects an unsupported conclusion.",
  date_inconsistency:
    "A fabricated chronological inconsistency (WHOIS date later than the first Wayback Machine capture) is added to the summary — never checked against the facts. Measures whether the verifier spots the inconsistency.",
  offtopic_recommendation:
    "A completely off-topic recommendation (e.g. a database migration) is added to the recommendations. Measures whether the verifier detects content unrelated to the analyzed domain.",
};

// Metric tile — the whole tile is the hover/focus target (not just an icon),
// with a discreet ⓘ as a visual cue.
function MetricTile({ label, value, std, tone, info }) {
  return (
    <div className={`metric-tile${info ? " has-info" : ""}`} tabIndex={info ? 0 : undefined}>
      <div className="metric-tile-label">{label}</div>
      <div className="metric-tile-value" style={{ color: tone }}>
        {value}
      </div>
      {std != null ? <div className="metric-tile-std">± {std} std dev</div> : null}
      {info ? (
        <>
          <span className="metric-tile-info-icon" aria-hidden="true">
            i
          </span>
          <span className="metric-tile-bubble" role="tooltip">
            {info}
          </span>
        </>
      ) : null}
    </div>
  );
}

// Explanation bubble for bar charts — positioned (as a % of viewBox
// coordinates) above the currently hovered/focused bar or error bar.
// `hover` is null when nothing is targeted.
function ChartTooltip({ hover }) {
  if (!hover) return null;
  return (
    <div className="chart-tooltip" style={{ left: `${hover.xPct}%`, top: `${hover.yPct}%` }}>
      {hover.text}
    </div>
  );
}

// With / without verifier bars for the hallucination rate (hard layer) —
// the harness's actual comparison axis (see docs/EVAL_PLAN.md), not a
// provider comparison, which doesn't exist within a given run.
//
// Each bar is the MEAN over all measurements (domains × repetitions) of the
// config, NOT just over one domain's repetitions (see
// evals/harness/cli.py:summarize — rows are pooled); the vertical line with
// two small caps is an ERROR BAR (standard statistical term, not just a
// "line") showing ± 1 standard deviation around that mean.
function VerifierChart({ withV, withoutV }) {
  const [hover, setHover] = useState(null);
  const bars = [
    {
      label: "Without verifier",
      mean: withoutV?.hallucination_hard_mean,
      std: withoutV?.hallucination_hard_std,
      n: withoutV?.n_runs_ok,
      color: "var(--red)",
    },
    {
      label: "With verifier",
      mean: withV?.hallucination_hard_mean,
      std: withV?.hallucination_hard_std,
      n: withV?.n_runs_ok,
      color: "var(--teal)",
    },
  ].filter((b) => b.mean != null);
  if (bars.length === 0) return <p className="hint">No hallucination data for this run.</p>;

  const W = 460;
  const H = 170;
  const pad = { top: 26, right: 20, bottom: 34, left: 40 };
  const chartW = W - pad.left - pad.right;
  const chartH = H - pad.top - pad.bottom;
  const max = Math.max(...bars.map((b) => b.mean + (b.std || 0))) * 1.25 || 0.1;
  const step = chartW / bars.length;
  const barW = Math.min(80, step * 0.45);
  const yTicks = [0, 0.25, 0.5, 0.75, 1];

  // Each displayed rate is a mean over N measurements (one domain × one
  // repetition = one measurement, see evals/harness/cli.py:summarize) — not a
  // single value. Make that concrete rather than talking about "standard
  // deviation" in the abstract.
  const barInfo = (b) =>
    `Bar: mean hallucination rate (hard layer) over the ${b.n ?? "?"} measurements of the "${b.label.toLowerCase()}" config (one domain of the run × one repetition = one measurement).`;
  const errorBarInfo = (b) =>
    `Error bar: these ${b.n ?? "?"} individual measurements didn't all give the same result — this bar shows how far they deviate on average from the displayed ${pct(b.mean)} (the standard deviation). The longer it is, the more the rate depends on which domain or repetition came up — not that the overall rate is high.`;

  return (
    <div className="chart-wrap">
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ overflow: "visible", display: "block" }}>
        {yTicks.map((f) => {
          const y = pad.top + chartH - f * chartH;
          return (
            <g key={f}>
              <line x1={pad.left} x2={pad.left + chartW} y1={y} y2={y} stroke="var(--border)" strokeWidth="1" />
              <text
                x={pad.left - 6}
                y={y + 3}
                textAnchor="end"
                style={{ fontFamily: "var(--font-mono)", fontSize: 9, fill: "var(--muted)" }}
              >
                {(max * f * 100).toFixed(0)}%
              </text>
            </g>
          );
        })}
        {bars.map((b, i) => {
          const x = pad.left + i * step + step / 2 - barW / 2;
          const h = (b.mean / max) * chartH;
          const y = pad.top + chartH - h;
          const stdH = ((b.std || 0) / max) * chartH;
          const cxPct = ((x + barW / 2) / W) * 100;
          return (
            <g key={b.label}>
              <rect
                x={x}
                y={y}
                width={barW}
                height={h}
                fill={b.color}
                opacity="0.75"
                rx="4"
                className="chart-hit"
                tabIndex={0}
                onMouseEnter={() => setHover({ xPct: cxPct, yPct: (y / H) * 100, text: barInfo(b) })}
                onMouseLeave={() => setHover(null)}
                onFocus={() => setHover({ xPct: cxPct, yPct: (y / H) * 100, text: barInfo(b) })}
                onBlur={() => setHover(null)}
              />
              {b.std ? (
                <>
                  <line x1={x + barW / 2} x2={x + barW / 2} y1={y - stdH} y2={y + stdH} stroke={b.color} strokeWidth="2" />
                  <line x1={x + barW / 2 - 5} x2={x + barW / 2 + 5} y1={y - stdH} y2={y - stdH} stroke={b.color} strokeWidth="1.5" />
                  <line x1={x + barW / 2 - 5} x2={x + barW / 2 + 5} y1={y + stdH} y2={y + stdH} stroke={b.color} strokeWidth="1.5" />
                  <rect
                    x={x + barW / 2 - 6}
                    y={y - stdH - 3}
                    width="12"
                    height={stdH * 2 + 6}
                    fill="transparent"
                    className="chart-hit"
                    tabIndex={0}
                    onMouseEnter={() => setHover({ xPct: cxPct, yPct: ((y - stdH) / H) * 100, text: errorBarInfo(b) })}
                    onMouseLeave={() => setHover(null)}
                    onFocus={() => setHover({ xPct: cxPct, yPct: ((y - stdH) / H) * 100, text: errorBarInfo(b) })}
                    onBlur={() => setHover(null)}
                  />
                </>
              ) : null}
              <text
                x={x + barW / 2}
                y={y - stdH - 8}
                textAnchor="middle"
                style={{ fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 600, fill: b.color }}
              >
                {(b.mean * 100).toFixed(1)}%
              </text>
              <text
                x={x + barW / 2}
                y={pad.top + chartH + 18}
                textAnchor="middle"
                style={{ fontFamily: "var(--font-mono)", fontSize: 10, fill: "var(--muted)" }}
              >
                {b.label}
              </text>
            </g>
          );
        })}
        <line x1={pad.left} x2={pad.left} y1={pad.top} y2={pad.top + chartH} stroke="var(--border)" strokeWidth="1" />
      </svg>
      <ChartTooltip hover={hover} />
    </div>
  );
}

// Comparison across runs (not across configs of one run, see VerifierChart
// above): the with-verifier hallucination rate, one point per run, in
// chronological order, colored by provider. Useful to spot drift or compare
// deepseek/mistral across separate runs.
function RunsComparisonChart({ runs }) {
  const [hover, setHover] = useState(null);
  const bars = [...runs]
    .filter((r) => r.hallucination_hard_with != null)
    .sort((a, b) => (a.generated_at || a.id).localeCompare(b.generated_at || b.id));
  if (bars.length === 0) return null;

  const W = 860;
  const H = 200;
  const pad = { top: 26, right: 20, bottom: 46, left: 44 };
  const chartW = W - pad.left - pad.right;
  const chartH = H - pad.top - pad.bottom;
  const max = Math.max(...bars.map((b) => b.hallucination_hard_with + (b.hallucination_hard_std_with || 0))) * 1.25 || 0.1;
  const step = chartW / bars.length;
  const barW = Math.min(56, step * 0.5);
  const yTicks = [0, 0.25, 0.5, 0.75, 1];

  // As in VerifierChart: each point is a mean over N measurements (domains ×
  // repetitions of THIS run), not a single value — make that concrete rather
  // than talking about "standard deviation" in the abstract.
  const barInfo = (b) => {
    const n = b.n_domains != null && b.n_repetitions != null ? b.n_domains * b.n_repetitions : null;
    return `Bar: mean hallucination rate (with verifier) over ${b.n_domains ?? "?"} domains × ${b.n_repetitions ?? "?"} repetitions${n != null ? ` (${n} measurements)` : ""} — run ${b.model || b.provider}.`;
  };
  const errorBarInfo = (b) =>
    `Error bar: these measurements didn't all give the same result — this bar shows how far they deviate on average from the displayed ${pct(b.hallucination_hard_with)} (the standard deviation). The longer it is, the more the rate depends on which domain or repetition came up. It does not tell you whether the difference with another run is significant.`;

  return (
    <div className="section" style={{ marginTop: "clamp(24px, 4vw, 34px)" }}>
      <div className="chart-head">
        <h2 style={{ margin: 0 }}>Hallucination (with verifier) — run comparison</h2>
        <div className="chart-legend">
          <span className="chart-legend-item">
            <span className="chart-swatch" style={{ background: "var(--teal)" }} /> DeepSeek
          </span>
          <span className="chart-legend-item">
            <span className="chart-swatch" style={{ background: "var(--amber)" }} /> Mistral
          </span>
        </div>
      </div>
      <div className="chart-wrap">
        <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ overflow: "visible", display: "block" }}>
          {yTicks.map((f) => {
            const y = pad.top + chartH - f * chartH;
            return (
              <g key={f}>
                <line x1={pad.left} x2={pad.left + chartW} y1={y} y2={y} stroke="var(--border)" strokeWidth="1" />
                <text
                  x={pad.left - 8}
                  y={y + 3}
                  textAnchor="end"
                  style={{ fontFamily: "var(--font-mono)", fontSize: 9, fill: "var(--muted)" }}
                >
                  {(max * f * 100).toFixed(0)}%
                </text>
              </g>
            );
          })}
          {bars.map((b, i) => {
            const x = pad.left + i * step + step / 2 - barW / 2;
            const h = (b.hallucination_hard_with / max) * chartH;
            const y = pad.top + chartH - h;
            const stdH = ((b.hallucination_hard_std_with || 0) / max) * chartH;
            const color = b.provider === "mistral" ? "var(--amber)" : "var(--teal)";
            const date = b.generated_at ? new Date(b.generated_at) : null;
            const cxPct = ((x + barW / 2) / W) * 100;
            return (
              <g key={b.id}>
                <rect
                  x={x}
                  y={y}
                  width={barW}
                  height={h}
                  fill={color}
                  opacity="0.75"
                  rx="4"
                  className="chart-hit"
                  tabIndex={0}
                  onMouseEnter={() => setHover({ xPct: cxPct, yPct: (y / H) * 100, text: barInfo(b) })}
                  onMouseLeave={() => setHover(null)}
                  onFocus={() => setHover({ xPct: cxPct, yPct: (y / H) * 100, text: barInfo(b) })}
                  onBlur={() => setHover(null)}
                />
                {b.hallucination_hard_std_with ? (
                  <>
                    <line x1={x + barW / 2} x2={x + barW / 2} y1={y - stdH} y2={y + stdH} stroke={color} strokeWidth="2" />
                    <line
                      x1={x + barW / 2 - 5}
                      x2={x + barW / 2 + 5}
                      y1={y - stdH}
                      y2={y - stdH}
                      stroke={color}
                      strokeWidth="1.5"
                    />
                    <line
                      x1={x + barW / 2 - 5}
                      x2={x + barW / 2 + 5}
                      y1={y + stdH}
                      y2={y + stdH}
                      stroke={color}
                      strokeWidth="1.5"
                    />
                    <rect
                      x={x + barW / 2 - 6}
                      y={y - stdH - 3}
                      width="12"
                      height={stdH * 2 + 6}
                      fill="transparent"
                      className="chart-hit"
                      tabIndex={0}
                      onMouseEnter={() => setHover({ xPct: cxPct, yPct: ((y - stdH) / H) * 100, text: errorBarInfo(b) })}
                      onMouseLeave={() => setHover(null)}
                      onFocus={() => setHover({ xPct: cxPct, yPct: ((y - stdH) / H) * 100, text: errorBarInfo(b) })}
                      onBlur={() => setHover(null)}
                    />
                  </>
                ) : null}
                <text
                  x={x + barW / 2}
                  y={y - stdH - 8}
                  textAnchor="middle"
                  style={{ fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 600, fill: color }}
                >
                  {(b.hallucination_hard_with * 100).toFixed(1)}%
                </text>
                <text
                  x={x + barW / 2}
                  y={pad.top + chartH + 16}
                  textAnchor="middle"
                  style={{ fontFamily: "var(--font-mono)", fontSize: 9, fill: "var(--muted)" }}
                >
                  {b.model || b.provider}
                </text>
                <text
                  x={x + barW / 2}
                  y={pad.top + chartH + 28}
                  textAnchor="middle"
                  style={{ fontFamily: "var(--font-mono)", fontSize: 8, fill: "var(--faint)" }}
                >
                  {date ? date.toLocaleDateString("en-US", { day: "2-digit", month: "2-digit" }) : ""}
                </text>
              </g>
            );
          })}
          <line x1={pad.left} x2={pad.left} y1={pad.top} y2={pad.top + chartH} stroke="var(--border)" strokeWidth="1" />
        </svg>
        <ChartTooltip hover={hover} />
      </div>
    </div>
  );
}

export default function Results() {
  const [runs, setRuns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [selectedId, setSelectedId] = useState(null);
  const [detail, setDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);

  useEffect(() => {
    apiFetch("/api/eval/runs")
      .then((r) => {
        if (!r.ok) throw new Error();
        return r.json();
      })
      .then(setRuns)
      .catch(() => setLoadError("Could not load evaluation runs."))
      .finally(() => setLoading(false));
  }, []);

  function selectRun(id) {
    if (selectedId === id) {
      setSelectedId(null);
      setDetail(null);
      return;
    }
    setSelectedId(id);
    setDetail(null);
    setDetailLoading(true);
    apiFetch(`/api/eval/runs/${id}`)
      .then((r) => {
        if (!r.ok) throw new Error();
        return r.json();
      })
      .then(setDetail)
      .catch(() => setDetail(null))
      .finally(() => setDetailLoading(false));
  }

  const withV = detail?.by_config?.with_verifier;
  const withoutV = detail?.by_config?.without_verifier;

  return (
    <>
      <div className="screen-header">
        <h1 className="screen-title">Evaluation results</h1>
        <p className="screen-sub">
          Eval harness runs (<code>evals/results/</code>, produced by <code>make eval</code>) —
          click a row for details.
        </p>
      </div>

      {loadError ? <div className="error">{loadError}</div> : null}

      {!loading && runs.length === 0 && !loadError ? (
        <div className="map-empty">
          No run found. Run <code>make eval</code> (or <code>make eval-quick</code>) to produce one.
        </div>
      ) : null}

      {runs.length > 0 ? (
        <div className="stream">
          <div className="stream-head">
            <span>
              {runs.length} run{runs.length > 1 ? "s" : ""}
            </span>
          </div>
          <div className="stream-body" style={{ padding: 0, maxHeight: "none" }}>
            <table className="runs-table">
              <thead>
                <tr>
                  <th>Date</th>
                  <th>Scenario</th>
                  <th>Provider</th>
                  <th>Model</th>
                  <th>Domains</th>
                  <th>Halluc. (with verif.)</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((run) => (
                  <tr
                    key={run.id}
                    className={selectedId === run.id ? "is-selected" : ""}
                    onClick={() => selectRun(run.id)}
                  >
                    <td>
                      <span className="mono-val">
                        {run.generated_at ? new Date(run.generated_at).toLocaleString("en-US") : run.id}
                      </span>
                    </td>
                    <td>{run.scenario || "—"}</td>
                    <td style={{ color: run.provider === "mistral" ? "var(--amber)" : "var(--teal)" }}>
                      {run.provider || "—"}
                    </td>
                    <td>
                      <span className="mono-val">{run.model || "—"}</span>
                    </td>
                    <td>
                      <span className="mono-val">
                        {run.n_domains ?? "—"} × {run.n_repetitions ?? "—"}
                      </span>
                    </td>
                    <td>{pct(run.hallucination_hard_with)}</td>
                    <td>
                      {run.run_error_rate_with == null ? (
                        "—"
                      ) : run.run_error_rate_with > 0 ? (
                        <span style={{ color: "var(--red)" }}>Partial errors</span>
                      ) : (
                        <span style={{ color: "var(--teal)" }}>OK</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}

      <RunsComparisonChart runs={runs} />

      {detailLoading ? <p className="hint">Loading details…</p> : null}

      {detail ? (
        <div className="report">
          <h2 className="report-title">
            {detail.meta?.scenario}{" "}
            <span className="dom">
              {detail.meta?.provider}/{detail.meta?.model}
            </span>
          </h2>

          <div className="section">
            <h2>With vs without verifier — hallucination (hard layer)</h2>
            <VerifierChart withV={withV} withoutV={withoutV} />
          </div>

          <div className="section">
            <h2>Metrics — with verifier</h2>
            <div className="metrics-grid">
              <MetricTile
                label="Hallucination (hard)"
                value={pct(withV?.hallucination_hard_mean)}
                std={withV?.hallucination_hard_std != null ? pct(withV.hallucination_hard_std) : null}
                tone="var(--red)"
                info={METRIC_INFO.hallucination_hard}
              />
              <MetricTile
                label="Completion"
                value={pct(withV?.completion_rate)}
                tone="var(--teal)"
                info={METRIC_INFO.completion}
              />
              <MetricTile
                label="Subdomain precision"
                value={pct(withV?.precision_mean)}
                std={withV?.precision_std != null ? pct(withV.precision_std) : null}
                tone="var(--ink)"
                info={METRIC_INFO.precision}
              />
              <MetricTile
                label="Subdomain recall"
                value={pct(withV?.recall_mean)}
                std={withV?.recall_std != null ? pct(withV.recall_std) : null}
                tone="var(--ink)"
                info={METRIC_INFO.recall}
              />
              <MetricTile
                label="Tokens / run"
                value={withV?.total_tokens_mean != null ? Math.round(withV.total_tokens_mean).toLocaleString("en-US") : "—"}
                std={withV?.total_tokens_std != null ? Math.round(withV.total_tokens_std).toLocaleString("en-US") : null}
                tone="var(--amber)"
                info={METRIC_INFO.tokens}
              />
              <MetricTile
                label="Latency"
                value={withV?.wall_seconds_mean != null ? `${num(withV.wall_seconds_mean)} s` : "—"}
                std={withV?.wall_seconds_std != null ? `${num(withV.wall_seconds_std)} s` : null}
                tone="var(--ink)"
                info={METRIC_INFO.latency}
              />
            </div>
          </div>

          <div className="section">
            <h2>Verifier detection (injected error families)</h2>
            <div className="metrics-grid">
              {Object.entries(detail.verifier_detection?.by_family || {}).map(([fam, rate]) => (
                <MetricTile
                  key={fam}
                  label={fam.replaceAll("_", " ")}
                  value={pct(rate)}
                  tone="var(--teal)"
                  info={FAMILY_INFO[fam]}
                />
              ))}
              <MetricTile
                label="False positives"
                value={pct(detail.verifier_detection?.false_positive_rate)}
                tone="var(--red)"
                info={METRIC_INFO.false_positive}
              />
            </div>
          </div>

          {detail.judge_soft ? (
            <div className="section">
              <h2>Qualitative judgment (LLM-as-judge)</h2>
              <div className="metrics-grid">
                <MetricTile
                  label="Hallucination (soft)"
                  value={pct(detail.judge_soft.hallucination_soft)}
                  tone="var(--red)"
                  info={METRIC_INFO.judge_hallucination_soft}
                />
                <MetricTile
                  label="Assertions met"
                  value={pct(detail.judge_soft.assertions_respected_rate)}
                  tone="var(--teal)"
                  info={METRIC_INFO.judge_assertions}
                />
              </div>
              <p className="hint">
                {detail.judge_soft.n_claims_judged} claims and {detail.judge_soft.n_assertions_judged} assertions
                judged across {detail.judge_soft.n_domains} domains.
              </p>
            </div>
          ) : null}
        </div>
      ) : null}
    </>
  );
}
