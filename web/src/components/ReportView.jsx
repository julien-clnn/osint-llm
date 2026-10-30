import InfraMap from "./InfraMap.jsx";
import { downloadText } from "../lib/download.js";

const RISK_LABEL = {
  low: "LOW",
  medium: "MEDIUM",
  high: "HIGH",
  undetermined: "UNDETERMINED",
};

const RISK_ICON = {
  low: "✓",
  medium: "!",
  high: "✕",
  undetermined: "?",
};

// Archived reports may still carry the legacy French risk_level values.
const LEGACY_RISK = {
  faible: "low",
  moyen: "medium",
  élevé: "high",
  indéterminé: "undetermined",
};

function normalizeRisk(level) {
  if (!level) return "undetermined";
  return LEGACY_RISK[level] || level;
}

// Dependency-free inline rendering: `code` and **bold**.
function inlineMarkdown(text, keyPrefix) {
  const nodes = [];
  const re = /(`[^`]+`|\*\*[^*]+\*\*)/g;
  let last = 0;
  let m;
  let i = 0;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) nodes.push(text.slice(last, m.index));
    const tok = m[0];
    if (tok.startsWith("`")) {
      nodes.push(<code key={`${keyPrefix}-c${i++}`}>{tok.slice(1, -1)}</code>);
    } else {
      nodes.push(<strong key={`${keyPrefix}-b${i++}`}>{tok.slice(2, -2)}</strong>);
    }
    last = m.index + tok.length;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}

// Detects a section heading line, whatever style the LLM uses:
//  "1. TITLE"  |  "**TITLE**"  |  "ALL-CAPS TITLE"
// Returns the cleaned-up title, or null if the line is not a heading.
function detectHeading(t) {
  let m = t.match(/^\s*\*\*(.+?)\*\*\s*:?\s*$/); // bold alone on the line
  if (m) return m[1].trim();
  m = t.match(/^\s*\d+[.)]\s+(.+?)\s*:?\s*$/); // numbered
  if (m && m[1].length <= 64 && !/[.!?]$/.test(m[1])) return m[1].trim();
  m = t.match(/^\s*([0-9A-ZÀÂÄÇÉÈÊËÎÏÔÖÙÛÜ][0-9A-ZÀÂÄÇÉÈÊËÎÏÔÖÙÛÜ '’&/().\-]{2,58})\s*:?\s*$/);
  if (m && !/[a-zàâäçéèêëîïôöùûü]/.test(m[1])) return m[1].trim(); // all caps
  return null;
}

// Splits the summary into an intro + sections, renumbered cleanly in order.
// Robust: with no recognized heading, everything falls back into the intro (bullets/paragraphs).
function parseSummary(summary) {
  const lines = String(summary).replace(/\r/g, "").split("\n");
  const intro = [];
  const sections = [];
  let current = null;

  for (const line of lines) {
    const t = line.trim();
    if (t === "") continue;
    const title = detectHeading(t);
    if (title !== null) {
      current = { num: String(sections.length + 1), title, items: [] };
      sections.push(current);
      continue;
    }
    const isBullet = /^[-*•]\s+/.test(t);
    const content = isBullet ? t.replace(/^[-*•]\s+/, "") : t;
    (current ? current.items : intro).push({ bullet: isBullet, text: content });
  }
  return { intro, sections };
}

// A "Label: value" bullet → bold label; plain text otherwise.
function Item({ entry, kp }) {
  const km = entry.text.match(/^([^:]{2,44}?)\s*:\s+(.+)$/s);
  if (km) {
    return (
      <li className={entry.bullet ? "synth-item bullet" : "synth-item"}>
        <span className="synth-k">{km[1]}</span>
        <span className="synth-v">{inlineMarkdown(km[2], kp)}</span>
      </li>
    );
  }
  return (
    <li className={entry.bullet ? "synth-item bullet" : "synth-item"}>
      <span className="synth-v">{inlineMarkdown(entry.text, kp)}</span>
    </li>
  );
}

function Synthesis({ summary }) {
  const text = summary || "";
  if (!text.trim()) return <p className="synth-empty">(no summary)</p>;
  const { intro, sections } = parseSummary(text);

  return (
    <div className="synth">
      {intro.length > 0 ? (
        <ul className="synth-items intro">
          {intro.map((e, i) => (
            <Item key={`in-${i}`} entry={e} kp={`in-${i}`} />
          ))}
        </ul>
      ) : null}
      {sections.map((sec, i) => (
        <div className="synth-sec" key={`sec-${i}`}>
          <div className="synth-sec-head">
            <span className="synth-num">{sec.num}</span>
            <h3>{sec.title}</h3>
          </div>
          {sec.items.length > 0 ? (
            <ul className="synth-items">
              {sec.items.map((e, j) => (
                <Item key={`s${i}-${j}`} entry={e} kp={`s${i}-${j}`} />
              ))}
            </ul>
          ) : null}
        </div>
      ))}
    </div>
  );
}

// "Verdict" card: the risk justification, tinted by risk level.
function RiskVerdict({ risk, justification }) {
  if (!justification) return null;
  return (
    <div className={`verdict risk-${risk}`}>
      <span className="verdict-icon" aria-hidden="true">
        {RISK_ICON[risk] || "?"}
      </span>
      <div className="verdict-body">
        <div className="verdict-top">
          <span className="verdict-label">Risk justification</span>
          <span className="verdict-level">
            {RISK_LABEL[risk] || risk.toUpperCase()} risk
          </span>
        </div>
        <p className="verdict-text">{justification}</p>
      </div>
    </div>
  );
}

// Audit banner: result of the verifier agent (2nd agent).
function VerificationBanner({ verification }) {
  if (!verification) return null;
  const {
    verified,
    corrected,
    iterations,
    unsupported_claims = [],
    corrections = [],
    remaining_unsupported_claims = [],
    notes = "",
  } = verification;

  const ok = verified;
  return (
    <div className={`verif ${ok ? "verif-ok" : "verif-warn"}`}>
      <div className="verif-head">
        <span className="verif-icon">{ok ? "✓" : "⚠"}</span>
        <strong>
          {ok
            ? corrected
              ? "Report corrected, then verified by the auditor agent"
              : "Report verified by the auditor agent"
            : "Report NOT verified — some claims may be unsupported by the facts"}
        </strong>
        <span className="verif-meta">
          {iterations} verification pass{iterations > 1 ? "es" : ""}
          {corrected ? " · corrected" : ""}
        </span>
      </div>
      {!ok && notes ? <p className="verif-notes">{notes}</p> : null}
      {remaining_unsupported_claims.length > 0 ? (
        <div className="verif-block">
          <span className="verif-label">Still unsupported after the last audit</span>
          <ul>
            {remaining_unsupported_claims.map((c, i) => (
              <li key={i}>{c}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {unsupported_claims.length > 0 ? (
        <div className="verif-block">
          <span className="verif-label">Claims flagged during the audit</span>
          <ul>
            {unsupported_claims.map((c, i) => (
              <li key={i}>{c}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {corrections.length > 0 ? (
        <div className="verif-block">
          <span className="verif-label">Applied corrections</span>
          <ul>
            {corrections.map((c, i) => (
              <li key={i}>{c}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

// Initial report (before verification), shown only if it was corrected.
function InitialReport({ initial }) {
  if (!initial) return null;
  const risk = normalizeRisk(initial.risk_level);
  return (
    <details className="initial">
      <summary>Show the initial report (before verification)</summary>
      <div className="initial-body">
        <p className="initial-risk">
          Initially estimated risk: <strong>{RISK_LABEL[risk] || risk}</strong>
        </p>
        <p>{initial.summary}</p>
      </div>
    </details>
  );
}

function AsnSection({ asn }) {
  if (!asn || asn.length === 0) return null;
  return (
    <div className="section">
      <h2>Network mapping (ASN)</h2>
      {asn.map((a, i) => (
        <div key={i} className="asn-card">
          <div className="asn-head">
            <span className="asn-num">AS{a.asn}</span>
            <strong>{a.asn_name || a.asn_description || "?"}</strong>
            <span className="asn-meta">
              {a.country ? `${a.country} · ` : ""}
              {a.prefix_count} IP range{a.prefix_count > 1 ? "s" : ""}
            </span>
          </div>
          {a.asn_prefixes && a.asn_prefixes.length > 0 ? (
            <div className="asn-prefixes">
              {a.asn_prefixes.map((p) => (
                <span key={p.prefix} className="prefix">
                  {p.prefix}
                </span>
              ))}
              {a.truncated ? <span className="prefix more">…+{a.prefix_count - a.asn_prefixes.length}</span> : null}
            </div>
          ) : null}
        </div>
      ))}
    </div>
  );
}

// Official page of an ATT&CK technique; null for a malformed ID (never build
// a link from an unchecked string).
function attackUrl(id) {
  const clean = String(id || "").trim().toUpperCase();
  if (!/^T\d{4}(\.\d{3})?$/.test(clean)) return null;
  return `https://attack.mitre.org/techniques/${clean.replace(".", "/")}`;
}

// Findings mapped to MITRE ATT&CK (optional: absent from reports produced
// without the ATT&CK layer, including archived results).
function AttackSection({ mappings }) {
  if (!mappings || mappings.length === 0) return null;
  return (
    <div className="section">
      <h2>MITRE ATT&amp;CK mapping</h2>
      {mappings.map((m, i) => {
        const url = attackUrl(m.technique_id);
        return (
          <div key={i} className="asn-card attack-card">
            <div className="asn-head">
              {url ? (
                <a className="asn-num" href={url} target="_blank" rel="noreferrer">
                  {m.technique_id}
                </a>
              ) : (
                <span className="asn-num">{m.technique_id}</span>
              )}
              <strong>{m.technique_name}</strong>
            </div>
            <p className="attack-finding">{m.finding}</p>
            {m.justification ? <p className="attack-why">{m.justification}</p> : null}
          </div>
        );
      })}
    </div>
  );
}

function GithubSection({ github }) {
  if (!github || github.length === 0) return null;
  const repos = github.flatMap((f) => f.repository_matches || []);
  const code = github.flatMap((f) => f.code_matches || []);
  if (repos.length === 0 && code.length === 0) return null;

  return (
    <div className="section">
      <h2>GitHub footprint</h2>
      {repos.length > 0 ? (
        <ul className="gh-list">
          {repos.map((r, i) => (
            <li key={i}>
              <a href={r.url} target="_blank" rel="noreferrer noopener">
                {r.repo}
              </a>
              {r.description ? <span className="gh-desc"> — {r.description}</span> : null}
            </li>
          ))}
        </ul>
      ) : null}
      {code.length > 0 ? (
        <>
          <p className="gh-sub">Code matches (potential secrets)</p>
          <ul className="gh-list">
            {code.map((c, i) => (
              <li key={i}>
                <a href={c.url} target="_blank" rel="noreferrer noopener">
                  {c.repo}/{c.path}
                </a>
              </li>
            ))}
          </ul>
        </>
      ) : null}
    </div>
  );
}

export default function ReportView({ report }) {
  const risk = normalizeRisk(report.risk_level);
  const subs = report.subdomains || [];
  const exports = report.exports || {};

  return (
    <section className="report">
      <h2 className="report-title">
        {report.verification && report.verification.verified === false
          ? "Unverified report"
          : "Verified report"}{" "}
        <span className="dom">{report.domain}</span>
        {report.mode ? (
          <span className={`mode-badge mode-${report.mode}`}>
            recon {report.mode === "active" ? "active" : "passive"}
            {report.proxy ? " · via proxy" : ""}
          </span>
        ) : null}
        {report.scenario ? (
          <span className="mode-badge">{report.scenario.label}</span>
        ) : null}
      </h2>

      <VerificationBanner verification={report.verification} />
      <p className="ai-disclaimer">
        Summary, verdict and recommendations are AI-generated: cross-check them
        against the raw facts below before acting on them.
      </p>

      <div className={`risk risk-${risk}`}>
        <span className="dot" />
        {report.verdict_label
          ? `Verdict: ${report.verdict_label.toUpperCase()}`
          : `Risk level: ${RISK_LABEL[risk] || risk.toUpperCase()}`}
      </div>

      {report.risk_justification ? (
        <div className="section">
          <h2>Verdict</h2>
          <RiskVerdict risk={risk} justification={report.risk_justification} />
        </div>
      ) : null}

      <div className="section">
        <h2>Summary</h2>
        <Synthesis summary={report.summary} />
      </div>

      {report.recommendations && report.recommendations.length > 0 ? (
        <div className="section">
          <h2>Recommendations</h2>
          <ul className="recos">
            {report.recommendations.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </div>
      ) : null}

      <AttackSection mappings={report.attack_mappings} />

      {report.verification && report.verification.corrected ? (
        <div className="section">
          <InitialReport initial={report.initial} />
        </div>
      ) : null}

      <div className="section">
        <h2>Infrastructure location</h2>
        <InfraMap locations={report.locations} />
      </div>

      <AsnSection asn={report.asn} />

      {subs.length > 0 ? (
        <div className="section">
          <h2>
            Discovered subdomains (
            {report.subdomain_total > subs.length
              ? `${subs.length} shown of ${report.subdomain_total}`
              : subs.length}
            )
          </h2>
          <details className="subs">
            <summary>Show all {subs.length} subdomains</summary>
            <div className="subs-grid">
              {subs.map((s) => (
                <div key={s}>{s}</div>
              ))}
            </div>
          </details>
        </div>
      ) : null}

      <GithubSection github={report.github} />

      <div className="section">
        <h2>Export report</h2>
        <div className="exports">
          <button
            onClick={() =>
              downloadText(`${report.domain}.json`, exports.json || "", "application/json")
            }
          >
            ⬇ JSON
          </button>
          <button
            onClick={() =>
              downloadText(`${report.domain}.md`, exports.markdown || "", "text/markdown")
            }
          >
            ⬇ Markdown
          </button>
          <button
            onClick={() =>
              downloadText(`${report.domain}.html`, exports.html || "", "text/html")
            }
          >
            ⬇ HTML
          </button>
        </div>
        <p className="hint">
          Tip: open the HTML in a browser, then Cmd/Ctrl+P → "Save as PDF".
        </p>
      </div>
    </section>
  );
}
