// Log of the agent's reasoning, fed live by the SSE stream.
// Each line appears with a small fadeUp animation for a smooth feel.

const TOOL_LABELS = {
  whois_lookup: "WHOIS",
  enumerate_subdomains: "Subdomains",
  ip_geolocate: "IP geolocation",
  asn_lookup: "ASN / IP ranges",
  github_search: "GitHub",
  attack_lookup: "MITRE ATT&CK",
  submit_report: "Report",
};

function toolLabel(name) {
  return TOOL_LABELS[name] || name;
}

// Minimal dependency-free markdown rendering for the LLM's "thoughts":
// inline `code` and **bold**, and "-" lines as bullets.
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
      nodes.push(<code key={`${keyPrefix}-${i++}`}>{tok.slice(1, -1)}</code>);
    } else {
      nodes.push(<strong key={`${keyPrefix}-${i++}`}>{tok.slice(2, -2)}</strong>);
    }
    last = m.index + tok.length;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}

function RichText({ text }) {
  const lines = String(text).split(/\n+/).filter((l) => l.trim() !== "");
  return lines.map((line, i) => {
    const isBullet = /^\s*[-*]\s+/.test(line);
    const content = isBullet ? line.replace(/^\s*[-*]\s+/, "") : line;
    return (
      <div key={i} className={isBullet ? "rt-bullet" : "rt-line"}>
        {inlineMarkdown(content, i)}
      </div>
    );
  });
}

function Line({ event }) {
  const { type, data } = event;

  if (type === "info") {
    return (
      <div className="line info">
        <span className="tag info">info</span>
        <span className="txt">{data.message}</span>
      </div>
    );
  }

  if (type === "assistant_message") {
    return (
      <div className="line think">
        <span className="tag think">llm</span>
        <span className="txt">
          <RichText text={data.content} />
        </span>
      </div>
    );
  }

  if (type === "tool_call") {
    if (data.name === "submit_report") {
      return (
        <div className="line">
          <span className="tag tool">report</span>
          <span className="txt">Writing the final report…</span>
        </div>
      );
    }
    return (
      <div className="line">
        <span className="tag tool">call</span>
        <span className="txt">
          <strong>{toolLabel(data.name)}</strong>
          {data.arguments ? <span className="mono"> {data.arguments}</span> : null}
        </span>
      </div>
    );
  }

  if (type === "tool_result") {
    if (data.ok) {
      return (
        <div className="line">
          <span className="tag ok">✓</span>
          <span className="txt">
            <strong>{toolLabel(data.name)}</strong> — data received
          </span>
        </div>
      );
    }
    return (
      <div className="line">
        <span className="tag warn">⚠</span>
        <span className="txt">
          <strong>{toolLabel(data.name)}</strong> — {data.error || "error"}
        </span>
      </div>
    );
  }

  if (type === "verification") {
    const n = (data.unsupported_claims || []).length;
    if (data.verified) {
      return (
        <div className="line">
          <span className="tag audit">audit</span>
          <span className="txt">Report verified — consistent with the collected facts.</span>
        </div>
      );
    }
    return (
      <div className="line">
        <span className="tag warn">audit</span>
        <span className="txt">
          {n > 0
            ? `${n} unsupported claim${n > 1 ? "s" : ""} — correction requested.`
            : data.notes || "Report not verified."}
        </span>
      </div>
    );
  }

  return null;
}

export default function ActivityStream({ events, status }) {
  const live = status === "running";
  const label =
    status === "running"
      ? "Analysis in progress"
      : status === "done"
        ? "Analysis complete"
        : "Analysis";

  return (
    <div className="stream">
      <div className="stream-head">
        <span className={`core ${live ? "live" : "done"}`} />
        {label}
      </div>
      <div className="stream-body">
        {events.map((ev, i) => (
          <Line key={i} event={ev} />
        ))}
      </div>
    </div>
  );
}
