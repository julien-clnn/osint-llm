"""Structured OSINT report.

Two things are deliberately kept apart:
  - FACTS: raw tool results, collected by the code (reliable, no possible
    hallucination);
  - ANALYSIS: summary, risk level and recommendations, produced by the LLM
    through the `submit_report` tool (enforced schema).

`OsintReport` can serialize itself to dict/JSON and render to Markdown/HTML.
"""

from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from typing import Any

# Allowed risk levels (enforced on the LLM through the tool schema).
RISK_LEVELS = ("low", "medium", "high", "undetermined")

# French values emitted before the English migration (archived runs in
# evals/results/, older saved reports).
LEGACY_RISK_LEVELS = {
    "faible": "low",
    "moyen": "medium",
    "élevé": "high",
    "indéterminé": "undetermined",
}


def normalize_risk_level(value: Any) -> str:
    """Map any risk value (English or legacy French) to a `RISK_LEVELS` entry."""
    risk = str(value or "").strip().lower()
    risk = LEGACY_RISK_LEVELS.get(risk, risk)
    return risk if risk in RISK_LEVELS else "undetermined"


# (background, text) color for each level, for the HTML rendering.
_RISK_COLORS = {
    "low": ("#1f7a3d", "#ffffff"),
    "medium": ("#b7791f", "#ffffff"),
    "high": ("#b91c1c", "#ffffff"),
    "undetermined": ("#6b7280", "#ffffff"),
}

# Lightly tinted background of the summary card, per risk level.
_RISK_TINTS = {
    "low": "#f0fdf4",
    "medium": "#fffbeb",
    "high": "#fef2f2",
    "undetermined": "#f9fafb",
}


_ATTACK_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def attack_url(technique_id: str) -> str | None:
    """Official ATT&CK page of a technique ID, None if the ID is malformed
    (never build a link from an unchecked string)."""
    technique_id = (technique_id or "").strip().upper()
    if not _ATTACK_ID_RE.match(technique_id):
        return None
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/")


def _summary_to_html(text: str) -> str:
    """Turn the summary (LLM free text) into readable HTML.

    - blocks separated by blank lines -> paragraphs;
    - blocks of lines starting with `-`, `•` or `*` -> bullet list.

    Avoids a "wall of text" by preserving structure when the model provides one.
    """
    text = (text or "").strip()
    if not text:
        return "<p><em>(no summary)</em></p>"

    e = html.escape
    out: list[str] = []
    for block in re.split(r"\n\s*\n", text):
        lines = [ln.strip() for ln in block.splitlines() if ln.strip()]
        if not lines:
            continue
        if all(re.match(r"^[-•*]\s+", ln) for ln in lines):
            items = "".join(
                f"<li>{e(re.sub(r'^[-•*]\s+', '', ln))}</li>" for ln in lines
            )
            out.append(f"<ul>{items}</ul>")
        else:
            out.append(f"<p>{e(' '.join(lines))}</p>")
    return "".join(out)


@dataclass
class OsintReport:
    """Investigation report on a domain."""

    domain: str

    # Analysis produced by the LLM.
    summary: str = ""
    risk_level: str = "undetermined"
    risk_justification: str = ""
    recommendations: list[str] = field(default_factory=list)

    # Findings mapped to MITRE ATT&CK techniques (ATT&CK layer, see
    # docs/RAG.md): [{finding, technique_id, technique_name, justification}].
    # Empty for reports produced without the layer, including archived ones.
    attack_mappings: list[dict[str, str]] = field(default_factory=list)

    # Raw facts: tool name -> list of calls {arguments, result}.
    collected: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    # Execution metadata.
    iterations: int = 0
    stopped_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "summary": self.summary,
            "risk_level": self.risk_level,
            "risk_justification": self.risk_justification,
            "recommendations": self.recommendations,
            "attack_mappings": self.attack_mappings,
            "collected": self.collected,
            "iterations": self.iterations,
            "stopped_reason": self.stopped_reason,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def to_markdown(self) -> str:
        """Render the report as readable Markdown."""
        lines: list[str] = [
            f"# OSINT report — {self.domain}",
            "",
            f"**Risk level: {normalize_risk_level(self.risk_level).upper()}**",
            "",
            "## Summary",
            self.summary or "_(no summary)_",
        ]

        if self.risk_justification:
            lines += ["", "## Risk justification", self.risk_justification]

        if self.recommendations:
            lines += ["", "## Recommendations"]
            lines += [f"- {reco}" for reco in self.recommendations]

        if self.attack_mappings:
            lines += ["", "## MITRE ATT&CK mapping", "",
                      "| Finding | Technique | Justification |", "|---|---|---|"]
            for m in self.attack_mappings:
                tid = m.get("technique_id", "")
                url = attack_url(tid)
                label = f"[{tid}]({url})" if url else tid
                cells = [m.get("finding", ""), f"{label} {m.get('technique_name', '')}".strip(),
                         m.get("justification", "")]
                lines.append("| " + " | ".join(c.replace("|", "\\|").replace("\n", " ")
                                                for c in cells) + " |")

        asns = self.asn_lookups()
        if asns:
            lines += ["", "## Network map (ASN)"]
            for a in asns:
                org = a.get("asn_name") or a.get("asn_description") or "?"
                lines.append(
                    f"- **AS{a.get('asn')} — {org}** "
                    f"({a.get('country') or '?'}) — {a.get('prefix_count', 0)} IP range(s)"
                )
                for p in a.get("asn_prefixes", []):
                    lines.append(f"  - `{p.get('prefix')}` {p.get('name') or ''}".rstrip())

        gh = self.github_findings()
        gh_repos = [r for f in gh for r in f.get("repository_matches", [])]
        gh_code = [c for f in gh for c in f.get("code_matches", [])]
        if gh_repos or gh_code:
            lines += ["", "## GitHub footprint"]
            if gh_repos:
                lines.append(f"**Related repositories ({len(gh_repos)})**")
                lines += [
                    f"- [{r.get('repo')}]({r.get('url')}) — {r.get('description') or ''}".rstrip()
                    for r in gh_repos
                ]
            if gh_code:
                lines.append("")
                lines.append(f"**Code matches ({len(gh_code)})**")
                lines += [
                    f"- [{c.get('repo')}/{c.get('path')}]({c.get('url')})"
                    for c in gh_code
                ]

        # Security posture: email (SPF/DMARC) + HTTP headers.
        dns = self.dns_records()
        fps = self.tech_fingerprints()
        if dns or fps:
            lines += ["", "## Security posture"]
            for d in dns:
                sec = d.get("email_security", {})
                mx = ", ".join(d.get("mx", [])) or "none"
                lines.append(
                    f"- **Email** ({d.get('domain')}): "
                    f"SPF {'✅' if sec.get('spf') else '❌'} · "
                    f"DMARC {'✅' if sec.get('dmarc') else '❌'}"
                    + (f" (policy `p={sec['dmarc_policy']}`)" if sec.get('dmarc_policy') else "")
                    + f" · MX: {mx}"
                )
            for f in fps:
                tech = ", ".join(f.get("detected_tech", [])) or "unknown"
                missing = ", ".join(f.get("security_headers_missing", [])) or "none"
                lines.append(
                    f"- **HTTP headers** ({f.get('domain')}): "
                    f"hardening {f.get('hardening_posture')} ({f.get('hardening_score')})"
                    f" · stack: {tech} · missing: {missing}"
                )

        # Infrastructure history: Wayback + VirusTotal passive DNS.
        wb = self.wayback_lookups()
        vts = self.virustotal_lookups()
        passive_dns = [p for v in vts for p in v.get("passive_dns", [])]
        if wb or passive_dns:
            lines += ["", "## Infrastructure history"]
            for w in wb:
                dr = w.get("date_range") or {}
                span = f"{dr.get('first', '?')} → {dr.get('last', '?')}" if dr else "?"
                lines.append(
                    f"- **Wayback** ({w.get('domain')}): {w.get('capture_count', 0)} capture(s) "
                    f"[{span}], {w.get('subdomain_count', 0)} archived subdomain(s)"
                )
                for u in w.get("interesting_urls", [])[:10]:
                    lines.append(f"  - ⚠️ `{u.get('url')}` ({u.get('timestamp')})")
            if passive_dns:
                lines.append(
                    f"- **Passive DNS (VirusTotal)**: {len(passive_dns)} historical IP(s)"
                )
                for p in passive_dns[:10]:
                    lines.append(
                        f"  - `{p.get('ip_address')}` (resolved: {p.get('last_resolved')})"
                    )

        # VirusTotal reputation.
        if vts:
            lines += ["", "## Reputation (VirusTotal)"]
            for v in vts:
                st = v.get("last_analysis_stats", {})
                cats = ", ".join(v.get("categories", [])) or "—"
                lines.append(
                    f"- **{v.get('domain')}**: reputation {v.get('reputation')} · "
                    f"engines → {st.get('malicious', 0)} malicious / "
                    f"{st.get('suspicious', 0)} suspicious / {st.get('harmless', 0)} harmless · "
                    f"categories: {cats}"
                )

        lines += ["", "## Collected data"]
        if not self.collected:
            lines.append("_(no data collected)_")
        else:
            for tool_name, calls in self.collected.items():
                lines.append(f"### {tool_name}")
                for call in calls:
                    args = call.get("arguments", {})
                    result = call.get("result", {})
                    lines.append(f"- Call `{args}`:")
                    lines.append("")
                    lines.append("```json")
                    lines.append(json.dumps(result, ensure_ascii=False, indent=2))
                    lines.append("```")

        lines += [
            "",
            "---",
            f"_{self.iterations} iteration(s) · stopped: {self.stopped_reason} · "
            "passive reconnaissance_",
        ]
        return "\n".join(lines)

    # --- Cross-cutting data extraction (reused by the UI and the HTML) ---

    def locations(self) -> list[dict[str, Any]]:
        """All collected geolocated IPs (ip-api dicts)."""
        points: list[dict[str, Any]] = []
        for call in self.collected.get("ip_geolocate", []):
            for loc in call.get("result", {}).get("locations", []):
                points.append(loc)
        return points

    def subdomains(self) -> list[str]:
        """Discovered subdomains, deduplicated and sorted."""
        subs: set[str] = set()
        for call in self.collected.get("enumerate_subdomains", []):
            subs.update(call.get("result", {}).get("subdomains", []))
        return sorted(subs)

    def subdomain_total(self) -> int:
        """Total number of subdomains found BEFORE the tool's cap.

        The `enumerate_subdomains` tool caps its list (see _MAX_SUBDOMAINS)
        but exposes the real count: surface it to signal truncation.
        """
        total = 0
        for call in self.collected.get("enumerate_subdomains", []):
            total = max(total, call.get("result", {}).get("subdomain_count", 0))
        return max(total, len(self.subdomains()))

    def asn_lookups(self) -> list[dict[str, Any]]:
        """Collected ASN maps (one per inspected IP), deduplicated by ASN."""
        seen: set[Any] = set()
        out: list[dict[str, Any]] = []
        for call in self.collected.get("asn_lookup", []):
            res = call.get("result", {})
            asn = res.get("asn")
            if asn is None or asn in seen:
                continue
            seen.add(asn)
            out.append(res)
        return out

    def github_findings(self) -> list[dict[str, Any]]:
        """Collected GitHub search results (one per query)."""
        return [
            call.get("result", {})
            for call in self.collected.get("github_search", [])
            if "error" not in call.get("result", {})
        ]

    def dns_records(self) -> list[dict[str, Any]]:
        """Collected DNS records (MX/TXT/NS + email posture)."""
        return [
            call.get("result", {})
            for call in self.collected.get("dns_records_lookup", [])
            if "error" not in call.get("result", {})
        ]

    def tech_fingerprints(self) -> list[dict[str, Any]]:
        """Collected technology fingerprints / header hardening."""
        return [
            call.get("result", {})
            for call in self.collected.get("tech_fingerprint", [])
            if "error" not in call.get("result", {})
        ]

    def wayback_lookups(self) -> list[dict[str, Any]]:
        """Collected Wayback histories (subdomains, URLs, date range)."""
        return [
            call.get("result", {})
            for call in self.collected.get("wayback_lookup", [])
            if "error" not in call.get("result", {})
        ]

    def virustotal_lookups(self) -> list[dict[str, Any]]:
        """Usable VirusTotal results (enabled and found)."""
        return [
            r
            for call in self.collected.get("virustotal_lookup", [])
            if (r := call.get("result", {})) and "error" not in r and r.get("found")
        ]

    def to_html(self) -> str:
        """Render a standalone, styled HTML report (printable to PDF)."""
        e = html.escape
        risk = normalize_risk_level(self.risk_level)
        bg, fg = _RISK_COLORS[risk]
        tint = _RISK_TINTS[risk]

        # "Stat pills": key figures above the summary, for an at-a-glance
        # scannable dashboard.
        _gh = self.github_findings()
        _gh_repos = [r for f in _gh for r in f.get("repository_matches", [])]
        _fps = self.tech_fingerprints()
        stat_defs: list[tuple[str, str]] = []
        _subs = self.subdomains()
        if _subs:
            _total = self.subdomain_total()
            stat_defs.append((str(_total or len(_subs)), "subdomains"))
        _locs = self.locations()
        if _locs:
            stat_defs.append((str(len(_locs)), "located IPs"))
        _asns = self.asn_lookups()
        if _asns:
            stat_defs.append((str(len(_asns)), "ASN"))
        if _gh_repos:
            stat_defs.append((str(len(_gh_repos)), "GitHub repos"))
        if _fps:
            postures = [f.get("hardening_posture") for f in _fps if f.get("hardening_posture")]
            if postures:
                stat_defs.append((str(postures[0]), "HTTP hardening"))
        stats_html = (
            "<div class='stats'>"
            + "".join(f"<span class='stat'><b>{e(v)}</b>{e(lbl)}</span>" for v, lbl in stat_defs)
            + "</div>"
            if stat_defs
            else ""
        )

        reco_items = "".join(f"<li>{e(r)}</li>" for r in self.recommendations)
        reco_block = (
            f"<h2>Recommendations</h2><ul>{reco_items}</ul>" if reco_items else ""
        )

        attack_rows = []
        for m in self.attack_mappings:
            tid = m.get("technique_id", "")
            url = attack_url(tid)
            tech = (
                f'<a href="{e(url)}">{e(tid)}</a>' if url else e(tid)
            ) + f" {e(m.get('technique_name', ''))}"
            attack_rows.append(
                f"<tr><td>{e(m.get('finding', ''))}</td><td>{tech}</td>"
                f"<td>{e(m.get('justification', ''))}</td></tr>"
            )
        attack_block = (
            "<h2>MITRE ATT&amp;CK mapping</h2><table><tr><th>Finding</th>"
            "<th>Technique</th><th>Justification</th></tr>" + "".join(attack_rows) + "</table>"
            if attack_rows
            else ""
        )

        justif_block = (
            f"<h2>Risk justification</h2><p>{e(self.risk_justification)}</p>"
            if self.risk_justification
            else ""
        )

        # IP location table.
        locs = self.locations()
        if locs:
            rows = "".join(
                "<tr>"
                f"<td>{e(str(loc.get('ip', '')))}</td>"
                f"<td>{e(str(loc.get('city') or ''))}, {e(str(loc.get('country') or ''))}</td>"
                f"<td>{e(str(loc.get('org') or loc.get('isp') or ''))}</td>"
                f"<td>{e(str(loc.get('as') or ''))}</td>"
                "</tr>"
                for loc in locs
            )
            loc_block = (
                "<h2>Infrastructure (geolocated IPs)</h2>"
                "<table><thead><tr><th>IP</th><th>Location</th>"
                "<th>Operator</th><th>AS</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>"
            )
        else:
            loc_block = ""

        # Subdomains.
        subs = self.subdomains()
        if subs:
            items = "".join(f"<li>{e(s)}</li>" for s in subs)
            total = self.subdomain_total()
            count = f"{len(subs)} shown of {total}" if total > len(subs) else str(len(subs))
            subs_block = (
                f"<h2>Discovered subdomains ({count})</h2>"
                f"<ul class='cols'>{items}</ul>"
            )
        else:
            subs_block = ""

        # ASN map / IP ranges.
        asns = self.asn_lookups()
        if asns:
            blocks = []
            for a in asns:
                prefixes = "".join(
                    f"<li><code>{e(str(p.get('prefix')))}</code> "
                    f"{e(str(p.get('name') or ''))}</li>"
                    for p in a.get("asn_prefixes", [])
                )
                blocks.append(
                    f"<h3>AS{e(str(a.get('asn')))} — "
                    f"{e(str(a.get('asn_name') or a.get('asn_description') or '?'))} "
                    f"({e(str(a.get('country') or '?'))})</h3>"
                    f"<p>{e(str(a.get('prefix_count', 0)))} registered IP range(s):</p>"
                    f"<ul class='cols'>{prefixes}</ul>"
                )
            asn_block = "<h2>Network map (ASN)</h2>" + "".join(blocks)
        else:
            asn_block = ""

        # GitHub footprint (repositories + code).
        gh = self.github_findings()
        gh_repos = [r for f in gh for r in f.get("repository_matches", [])]
        gh_code = [c for f in gh for c in f.get("code_matches", [])]
        if gh_repos or gh_code:
            parts = ["<h2>GitHub footprint</h2>"]
            if gh_repos:
                items = "".join(
                    f"<li><a href='{e(str(r.get('url')))}'>{e(str(r.get('repo')))}</a>"
                    f" — {e(str(r.get('description') or ''))}</li>"
                    for r in gh_repos
                )
                parts.append(f"<h3>Related repositories ({len(gh_repos)})</h3><ul>{items}</ul>")
            if gh_code:
                items = "".join(
                    f"<li><a href='{e(str(c.get('url')))}'>"
                    f"{e(str(c.get('repo')))}/{e(str(c.get('path')))}</a></li>"
                    for c in gh_code
                )
                parts.append(
                    f"<h3>Code matches ({len(gh_code)})</h3><ul>{items}</ul>"
                )
            gh_block = "".join(parts)
        else:
            gh_block = ""

        # Security posture (email SPF/DMARC + HTTP headers).
        dns = self.dns_records()
        fps = self.tech_fingerprints()
        if dns or fps:
            rows = []
            for d in dns:
                sec = d.get("email_security", {})
                policy = (
                    f" (p={e(str(sec.get('dmarc_policy')))})" if sec.get("dmarc_policy") else ""
                )
                rows.append(
                    "<tr>"
                    f"<td>Email — {e(str(d.get('domain')))}</td>"
                    f"<td>SPF {'✅' if sec.get('spf') else '❌'} · "
                    f"DMARC {'✅' if sec.get('dmarc') else '❌'}{policy}</td>"
                    f"<td>MX: {e(', '.join(d.get('mx', [])) or 'none')}</td>"
                    "</tr>"
                )
            for f in fps:
                tech = e(", ".join(f.get("detected_tech", [])) or "unknown")
                missing = e(", ".join(f.get("security_headers_missing", [])) or "none")
                rows.append(
                    "<tr>"
                    f"<td>Headers — {e(str(f.get('domain')))}</td>"
                    f"<td>Hardening {e(str(f.get('hardening_posture')))} "
                    f"({e(str(f.get('hardening_score')))}) · missing: {missing}</td>"
                    f"<td>Stack: {tech}</td>"
                    "</tr>"
                )
            sec_block = (
                "<h2>Security posture</h2>"
                "<table><thead><tr><th>Area</th><th>Finding</th>"
                "<th>Detail</th></tr></thead>"
                f"<tbody>{''.join(rows)}</tbody></table>"
            )
        else:
            sec_block = ""

        # Infrastructure history (Wayback + passive DNS).
        wb = self.wayback_lookups()
        vts = self.virustotal_lookups()
        passive_dns = [p for v in vts for p in v.get("passive_dns", [])]
        if wb or passive_dns:
            parts = ["<h2>Infrastructure history</h2>"]
            for w in wb:
                dr = w.get("date_range") or {}
                span = (
                    f"{e(str(dr.get('first', '?')))} → {e(str(dr.get('last', '?')))}"
                    if dr
                    else "?"
                )
                parts.append(
                    f"<h3>Wayback — {e(str(w.get('domain')))}</h3>"
                    f"<p>{e(str(w.get('capture_count', 0)))} capture(s) [{span}] · "
                    f"{e(str(w.get('subdomain_count', 0)))} archived subdomain(s)</p>"
                )
                interesting = w.get("interesting_urls", [])
                if interesting:
                    items = "".join(
                        f"<li>⚠️ <code>{e(str(u.get('url')))}</code> "
                        f"({e(str(u.get('timestamp')))})</li>"
                        for u in interesting[:15]
                    )
                    parts.append(f"<ul>{items}</ul>")
            if passive_dns:
                items = "".join(
                    f"<li><code>{e(str(p.get('ip_address')))}</code> "
                    f"(resolved: {e(str(p.get('last_resolved')))})</li>"
                    for p in passive_dns[:15]
                )
                parts.append(
                    f"<h3>Passive DNS (VirusTotal) — {len(passive_dns)} IP</h3>"
                    f"<ul class='cols'>{items}</ul>"
                )
            infra_block = "".join(parts)
        else:
            infra_block = ""

        # VirusTotal reputation.
        if vts:
            rows = "".join(
                "<tr>"
                f"<td>{e(str(v.get('domain')))}</td>"
                f"<td>{e(str(v.get('reputation')))}</td>"
                f"<td>{e(str(v.get('last_analysis_stats', {}).get('malicious', 0)))} / "
                f"{e(str(v.get('last_analysis_stats', {}).get('suspicious', 0)))} / "
                f"{e(str(v.get('last_analysis_stats', {}).get('harmless', 0)))}</td>"
                f"<td>{e(', '.join(v.get('categories', [])) or '—')}</td>"
                "</tr>"
                for v in vts
            )
            vt_block = (
                "<h2>Reputation (VirusTotal)</h2>"
                "<table><thead><tr><th>Domain</th><th>Reputation</th>"
                "<th>Malicious / Suspicious / Harmless</th><th>Categories</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>"
            )
        else:
            vt_block = ""

        raw = e(json.dumps(self.to_dict(), ensure_ascii=False, indent=2))

        return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OSINT report — {e(self.domain)}</title>
<style>
  :root {{ color-scheme: light; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         max-width: 820px; margin: 2rem auto; padding: 1rem 1.2rem; color: #1a1a1a;
         background: #ffffff; line-height: 1.5; }}
  h1 {{ margin-bottom: .2rem; }}
  h2 {{ margin-top: 1.8rem; border-bottom: 1px solid #e5e7eb; padding-bottom: .3rem; }}
  .badge {{ display: inline-block; padding: .3rem .8rem; border-radius: 999px;
            font-weight: 600; background: {bg}; color: {fg}; white-space: nowrap; }}
  .synthesis {{ border: 1px solid #e5e7eb; border-left: 5px solid {bg};
                border-radius: 10px; background: {tint};
                padding: 1.1rem 1.3rem; margin: 1.2rem 0 1.6rem; }}
  .synthesis-head {{ display: flex; align-items: center; justify-content: space-between;
                     gap: .8rem; flex-wrap: wrap; }}
  .synthesis-head h2 {{ margin: 0; border: none; padding: 0; }}
  .stats {{ display: flex; flex-wrap: wrap; gap: .5rem; margin: .9rem 0 .2rem; }}
  .stat {{ background: #ffffff; border: 1px solid #e5e7eb; border-radius: 8px;
           padding: .35rem .65rem; font-size: .78rem; color: #6b7280; line-height: 1.25; }}
  .stat b {{ display: block; font-size: 1.15rem; color: #111827; font-weight: 700; }}
  .synthesis-body {{ margin-top: .4rem; }}
  .synthesis-body p {{ margin: .55rem 0; }}
  .synthesis-body p:first-child {{ margin-top: .2rem; }}
  .synthesis-body ul {{ margin: .5rem 0; padding-left: 1.2rem; }}
  .synthesis-body li {{ margin: .25rem 0; }}
  table {{ border-collapse: collapse; width: 100%; font-size: .92rem; }}
  th, td {{ text-align: left; padding: .4rem .6rem; border-bottom: 1px solid #e5e7eb; }}
  th {{ background: #f3f4f6; }}
  ul.cols {{ columns: 2; font-size: .9rem; }}
  details {{ margin-top: 1rem; }}
  pre {{ background: #f6f8fa; padding: 1rem; overflow-x: auto; font-size: .8rem;
         border-radius: 6px; }}
  footer {{ margin-top: 2rem; color: #6b7280; font-size: .85rem;
            border-top: 1px solid #e5e7eb; padding-top: .8rem; }}
</style>
</head>
<body>
  <h1>OSINT report — {e(self.domain)}</h1>

  <section class="synthesis">
    <div class="synthesis-head">
      <h2>Summary</h2>
      <span class="badge">Risk: {e(risk.upper())}</span>
    </div>
    {stats_html}
    <div class="synthesis-body">{_summary_to_html(self.summary)}</div>
  </section>

  {justif_block}
  {reco_block}
  {attack_block}
  {sec_block}
  {loc_block}
  {asn_block}
  {subs_block}
  {infra_block}
  {gh_block}
  {vt_block}

  <details>
    <summary>Raw collected data (JSON)</summary>
    <pre>{raw}</pre>
  </details>

  <footer>
    {self.iterations} iteration(s) · stopped: {e(self.stopped_reason)} ·
    passive reconnaissance · generated by osintllm
  </footer>
</body>
</html>"""
