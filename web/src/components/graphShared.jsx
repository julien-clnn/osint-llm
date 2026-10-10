// SVG building blocks shared by the live architecture graphs (AgentGraph for
// the Analysis screen, BenchmarkGraph for the Benchmark screen): same tools,
// same layout, same nodes/edges — only the derivation of the "live" state
// differs (a single run vs. several concurrent tasks).

import { useLayoutEffect, useRef, useState } from "react";

// ─── Tools actually exposed to the agent, per scenario ─────────────────────
// Mirrors scenarios/*.yaml (`tools:` field) — null = no restriction,
// all tools of the passive/active mode.
export const SCENARIO_TOOLS = {
  external_recon: null,
  email_security_posture: ["dns_records_lookup", "enumerate_subdomains"],
  phishing_triage: ["whois_lookup", "virustotal_lookup", "wayback_lookup"],
};

// Order = registry order (src/osintllm/tools/__init__.py::ALL_TOOLS).
export const TOOL_META = {
  whois_lookup: {
    label: "WHOIS",
    source: "WHOIS registries",
    renvoie: "registrar, dates, name servers, registrant",
    passive: true,
  },
  dns_records_lookup: {
    label: "DNS records",
    source: "DNS resolver",
    renvoie: "MX, TXT, NS + SPF/DMARC posture",
    passive: true,
  },
  enumerate_subdomains: {
    label: "Subdomains",
    source: "crt.sh (CT logs)",
    renvoie: "list of known subdomains",
    passive: true,
  },
  ip_geolocate: {
    label: "IP geolocation",
    source: "ip-api.com",
    renvoie: "country, city, coordinates, operator (AS)",
    passive: true,
  },
  asn_lookup: {
    label: "ASN / IP ranges",
    source: "bgpview.io + RIPEstat",
    renvoie: "the organization's ASN + all its IP ranges",
    passive: true,
  },
  wayback_lookup: {
    label: "Wayback Machine",
    source: "web.archive.org (CDX)",
    renvoie: "historically archived subdomains/URLs",
    passive: true,
  },
  tech_fingerprint: {
    label: "Tech fingerprint",
    source: "the target (1 HTTP request)",
    renvoie: "tech stack + header hardening",
    passive: false,
  },
  github_search: {
    label: "GitHub search",
    source: "api.github.com (Search)",
    renvoie: "related repos + exposed code (potential secrets)",
    passive: true,
  },
  virustotal_lookup: {
    label: "VirusTotal",
    source: "VirusTotal (API v3)",
    renvoie: "reputation + passive DNS (associated IPs)",
    passive: true,
  },
};
export const TOOL_ORDER = Object.keys(TOOL_META);

export function toolsForRun(mode, scenarioName) {
  const restriction = SCENARIO_TOOLS[scenarioName] ?? null;
  const base = restriction ?? TOOL_ORDER;
  return TOOL_ORDER.filter(
    (name) => base.includes(name) && (mode === "active" || TOOL_META[name].passive)
  );
}

// ─── Layout ─────────────────────────────────────────────────────────────────
export const VB_W = 900;
export const NODE_W = 190;
export const NODE_H = 60;
export const TOOL_W = 148;
export const TOOL_H = 46;

// Vertical rhythm of the "OSINT tools" frame (border → title → first row of
// cards → bottom border), in viewBox units.
export const CLUSTER_PAD_TOP = 16;
export const CLUSTER_TITLE_ASCENT = 10.5;
export const CLUSTER_TITLE_H = 13;
export const CLUSTER_GAP_AFTER_TITLE = 16;
export const CLUSTER_PAD_BOTTOM = 16;
export const CLUSTER_HEADER_H = CLUSTER_PAD_TOP + CLUSTER_TITLE_H + CLUSTER_GAP_AFTER_TITLE;

export function toolLayout(names) {
  const perRow = names.length > 5 ? Math.ceil(names.length / 2) : names.length;
  const gapX = 14;
  const gapY = 12;
  const startY = 318;
  return names.map((name, i) => {
    const row = Math.floor(i / perRow);
    const col = i % perRow;
    const itemsInRow = row === 0 ? Math.min(perRow, names.length) : names.length - perRow;
    const rowW = itemsInRow * TOOL_W + (itemsInRow - 1) * gapX;
    const rowStartX = (VB_W - rowW) / 2 + TOOL_W / 2;
    return {
      name,
      cx: rowStartX + col * (TOOL_W + gapX),
      cy: startY + row * (TOOL_H + gapY),
    };
  });
}

// Rounded elbow connector (vertical → horizontal → vertical).
export function roundedVElbow(x0, y0, x1, y1, r) {
  const my = (y0 + y1) / 2;
  const rr = Math.max(0, Math.min(r, Math.abs(y1 - y0) / 2 - 1, Math.abs(x1 - x0) / 2));
  const sx = x1 > x0 ? 1 : x1 < x0 ? -1 : 0;
  if (rr === 0 || sx === 0) return `M ${x0},${y0} L ${x1},${y1}`;
  return [
    `M ${x0},${y0}`,
    `L ${x0},${my - rr}`,
    `Q ${x0},${my} ${x0 + sx * rr},${my}`,
    `L ${x1 - sx * rr},${my}`,
    `Q ${x1},${my} ${x1},${my + rr}`,
    `L ${x1},${y1}`,
  ].join(" ");
}

// ─── Subcomponents ──────────────────────────────────────────────────────────

export function GraphNode({ x, y, w, h, label, sub, kind, active, flashOk, onClick }) {
  const r = 10;
  return (
    <g
      className={[
        "gnode",
        `gnode-${kind}`,
        active ? "is-active" : "",
        flashOk === true ? "is-flash-ok" : "",
        flashOk === false ? "is-flash-warn" : "",
        onClick ? "is-clickable" : "",
      ].join(" ")}
      onClick={onClick}
    >
      {active ? (
        <rect x={x - 5} y={y - 5} width={w + 10} height={h + 10} rx={r + 3} className="gnode-halo" />
      ) : null}
      <rect x={x} y={y} width={w} height={h} rx={r} className="gnode-body" />
      <rect x={x + 1} y={y + r} width={3} height={h - 2 * r} rx={1.5} className="gnode-accent" />
      <text x={x + 14} y={y + h / 2 - 8} className="gnode-label">
        {label}
      </text>
      <text x={x + 14} y={y + h / 2 + 10} className="gnode-sub">
        {sub}
      </text>
    </g>
  );
}

// Solid badge (background + rounded border) behind an edge's text,
// sized exactly to the label's real width via getBBox().
export function EdgeLabel({ x, y, text }) {
  const textRef = useRef(null);
  const [box, setBox] = useState(null);

  useLayoutEffect(() => {
    if (textRef.current) setBox(textRef.current.getBBox());
  }, [text]);

  return (
    <g className="gedge-label-group">
      {box ? (
        <rect
          x={box.x - 6}
          y={box.y - 3}
          width={box.width + 12}
          height={box.height + 6}
          rx={6}
          className="gedge-label-bg"
        />
      ) : null}
      <text ref={textRef} x={x} y={y} className="gedge-label" textAnchor="middle">
        {text}
      </text>
    </g>
  );
}

export function Edge({ path, label, lx, ly, dashed, active, muted }) {
  // An SVG marker is not part of the tree of the <path> that references it
  // (it lives in <defs>), so descendant CSS selectors can't color it via the
  // cascade. Pick the pre-colored marker matching the state instead.
  const markerId = active ? "gedge-arrow-active" : "gedge-arrow";
  return (
    <g className={["gedge", dashed ? "is-dashed" : "", active ? "is-active" : "", muted ? "is-muted" : ""].join(" ")}>
      <path d={path} className="gedge-path" markerEnd={`url(#${markerId})`} />
      {label ? <EdgeLabel x={lx} y={ly} text={label} /> : null}
    </g>
  );
}

export function DetailPanel({ title, kindLabel, lines, onClose }) {
  return (
    <aside className="graph-detail">
      <button className="graph-detail-close" onClick={onClose} aria-label="Close">
        ×
      </button>
      <p className="graph-detail-title">{title}</p>
      <p className="graph-detail-kind">{kindLabel}</p>
      <ul className="graph-detail-list">
        {lines.map((l, i) => (
          <li key={i}>{l}</li>
        ))}
      </ul>
    </aside>
  );
}

export function GraphDefs() {
  return (
    <defs>
      <marker id="gedge-arrow" markerWidth="7" markerHeight="7" refX="5.5" refY="3.5" orient="auto" markerUnits="strokeWidth">
        <path d="M 0 0 L 7 3.5 L 0 7 z" className="gedge-arrowhead" />
      </marker>
      <marker id="gedge-arrow-active" markerWidth="7" markerHeight="7" refX="5.5" refY="3.5" orient="auto" markerUnits="strokeWidth">
        <path d="M 0 0 L 7 3.5 L 0 7 z" className="gedge-arrowhead-active" />
      </marker>
    </defs>
  );
}
