"""Build the retrieval eval observations from the recorded tool fixtures.

Each observation is a REAL finding read from `evals/fixtures/<domain>/`
(recorded 2026-09-12, see evals/DATASET.md) by deterministic rules — no
model writes them, so the queries carry no bias toward the retriever or the
labelers. Each finding is rendered in 3 phrasings to measure stability to
rephrasing:
  - terse:   a tool-like note ("dmarc: p=none; spf: ~all");
  - analyst: one full sentence, with the domain;
  - agent:   a short search-style query, as the agent would send it.

Templates state facts only, without any attack interpretation ("spoofing",
"phishing"…): the agent may add such words in real runs, so these scores are
a conservative estimate. Limits (documented in docs/RAG.md): coverage is
bounded by what the 15 fixtures contain (e.g. no leaked secret on GitHub).

Usage:
    python evals/rag/extract_observations.py   # writes evals/rag/observations.json
"""

from __future__ import annotations

import glob
import json
import re
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from evals.rag.labeling import OBSERVATIONS  # noqa: E402

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
RECORDED_ON = date(2026, 9, 12)  # evals/DATASET.md

_SENSITIVE_SUB = re.compile(
    r"(^|[.-])(dev\d*|staging|stage|preprod|test|qa|uat|admin\w*|\w*admin|vpn|git|jenkins|"
    r"internal|intranet|backup|jira|grafana|kibana)([.-]|$)"
)
_SENSITIVE_PATH = re.compile(
    r"/(admin|administrator|login|wp-admin|wp-login\.php|phpmyadmin|\.git|\.env|"
    r"backup[^/]*|config(?:\.(?:php|ini|ya?ml|json|xml|bak|old|txt))?|db[^/]*\.sql|dump[^/]*)"
    r"(/|$|\?)",
    re.I,
)
_BLOCKLIST_HINT = re.compile(r"block|filter|urlhaus|phish|malware|hosts", re.I)
_LEET = re.compile(r"[a-z][013][a-z]")


def _result(domain_dir: Path, tool: str) -> dict[str, Any]:
    files = sorted(glob.glob(str(domain_dir / f"{tool}__*.json")))
    if not files:
        return {}
    result = json.loads(Path(files[0]).read_text(encoding="utf-8"))["result"]
    return result if isinstance(result, dict) else {}


def _first_date(value: Any) -> date | None:
    if isinstance(value, list):
        value = value[0] if value else None
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value)).date()
    except ValueError:
        return None


def _obs(domain: str, category: str, terse: str, analyst: str, agent: str) -> dict:
    return {
        "category": category,
        "grounded_in": domain,
        "phrasings": {"terse": terse, "analyst": analyst, "agent": agent},
    }


def email_auth(domain: str, d: Path) -> list[dict]:
    sec = _result(d, "dns_records_lookup").get("email_security") or {}
    if not sec:
        return []
    out = []
    spf = sec.get("spf_record") or ""
    qualifier = re.search(r"([~?+-])all\b", spf)
    if not sec.get("spf"):
        out.append(_obs(domain, "email_auth", "spf: none",
                        f"{domain} publishes no SPF record in its DNS TXT records.",
                        "domain without SPF record, any server can send mail as it"))
    elif qualifier and qualifier.group(1) in "~?+":
        q = qualifier.group(1) + "all"
        out.append(_obs(domain, "email_auth", f"spf: {q} (not -all)",
                        f"The SPF record of {domain} ends with {q} instead of -all, so "
                        "unauthorized senders are not rejected.",
                        f"SPF record ending with {q}, unauthorized senders not rejected"))
    if not sec.get("dmarc"):
        out.append(_obs(domain, "email_auth", "dmarc: none",
                        f"{domain} has no DMARC record (_dmarc TXT missing).",
                        "no DMARC policy published for the domain"))
    elif (sec.get("dmarc_policy") or "").lower() == "none":
        out.append(_obs(domain, "email_auth", "dmarc: p=none",
                        f"The DMARC policy of {domain} is p=none: failing messages are "
                        "only reported, never quarantined or rejected.",
                        "DMARC p=none monitoring only, mail failing authentication still "
                        "delivered"))
    return out


def registration(domain: str, d: Path) -> list[dict]:
    whois = _result(d, "whois_lookup")
    out = []
    created = _first_date(whois.get("creation_date"))
    if created and (RECORDED_ON - created).days < 365:
        days = (RECORDED_ON - created).days
        registrar = whois.get("registrar") or "unknown registrar"
        country = whois.get("registrant_country") or "undisclosed"
        out.append(_obs(domain, "registration",
                        f"whois: created {days} days ago, registrar {registrar}, "
                        f"registrant country {country}, no registrant org",
                        f"{domain} was registered only {days} days before the analysis, "
                        f"through {registrar}, with no registrant organization disclosed.",
                        f"newly registered domain ({days} days old) with hidden registrant"))
    label = domain.split(".")[0]
    if _LEET.search(label):
        out.append(_obs(domain, "registration",
                        f"name: {label} (digits in place of letters)",
                        f"The domain name {domain} imitates ordinary words by replacing "
                        "letters with look-alike digits.",
                        f"look-alike domain name {domain} using digits instead of letters"))
    return out


def reputation(domain: str, d: Path) -> list[dict]:
    out = []
    vt = _result(d, "virustotal_lookup")
    stats = vt.get("last_analysis_stats") or {}
    malicious = stats.get("malicious") or 0
    if malicious:
        total = sum(v for v in stats.values() if isinstance(v, int))
        out.append(_obs(domain, "reputation",
                        f"virustotal: {malicious}/{total} engines malicious",
                        f"On VirusTotal, {malicious} of {total} security engines flag {domain} "
                        "as malicious.",
                        f"domain flagged malicious by {malicious} VirusTotal engines"))
    gh = _result(d, "github_search")
    lists = sorted({m.get("repo", "") for m in gh.get("code_matches", [])
                    if _BLOCKLIST_HINT.search(m.get("path", "") + m.get("repo", ""))})
    if malicious and lists:
        out.append(_obs(domain, "reputation",
                        f"github: listed in blocklists ({', '.join(lists[:3])})",
                        f"{domain} appears in public malicious-URL blocklists hosted on "
                        f"GitHub ({', '.join(lists[:3])}).",
                        "domain present in public malicious URL blocklists"))
    return out


def subdomains(domain: str, d: Path) -> list[dict]:
    subs = _result(d, "enumerate_subdomains")
    names = subs.get("subdomains") or []
    out = []
    sensitive = [s for s in names if s != domain and _SENSITIVE_SUB.search(s[: -len(domain)])]
    if sensitive:
        shown = ", ".join(sensitive[:4])
        out.append(_obs(domain, "subdomains",
                        f"crt.sh: {len(sensitive)} non-production subdomains ({shown})",
                        f"Certificate Transparency logs for {domain} reveal non-production or "
                        f"administrative hostnames such as {shown}.",
                        f"certificate transparency exposes dev/admin subdomains like {shown}"))
    count = subs.get("subdomain_count") or 0
    if count >= 1000:
        out.append(_obs(domain, "subdomains",
                        f"crt.sh: {count} subdomains",
                        f"Certificate Transparency logs list {count} distinct subdomains of "
                        f"{domain}, a very large externally visible host inventory.",
                        f"{count} subdomains enumerated from certificate logs"))
    return out


def wayback(domain: str, d: Path) -> list[dict]:
    wb = _result(d, "wayback_lookup")
    urls = [u.get("url", "") for u in wb.get("interesting_urls", [])]
    paths = sorted({m.group(1).lower() for u in urls if (m := _SENSITIVE_PATH.search(u))})
    if not paths:
        return []
    shown = ", ".join(f"/{p}" for p in paths[:5])
    return [_obs(domain, "wayback",
                 f"wayback: archived {shown}",
                 f"The Wayback Machine has archived sensitive paths on {domain}: {shown}.",
                 f"archived admin/login pages {shown} in Wayback history")]


def http_fingerprint(domain: str, d: Path) -> list[dict]:
    fp = _result(d, "tech_fingerprint")
    missing = fp.get("security_headers_missing") or []
    if not missing:
        return []
    shown = ", ".join(missing)
    return [_obs(domain, "http_fingerprint",
                 f"headers missing: {shown}",
                 f"The home page of {domain} is served without the {shown} security headers.",
                 f"web server missing security headers {shown}")]


def infrastructure(domain: str, d: Path) -> list[dict]:
    dns = _result(d, "dns_records_lookup")
    whois = _result(d, "whois_lookup")
    out = []
    if dns and not dns.get("mx_count") and not dns.get("ns_count") and whois.get("name_servers"):
        ns = ", ".join(n.lower() for n in whois["name_servers"][:2])
        out.append(_obs(domain, "infrastructure",
                        f"dns: no MX/TXT records, NS {ns}",
                        f"{domain} resolves through {ns} but publishes no MX or TXT record.",
                        f"domain behind {ns} with no mail or TXT records"))
    if (whois.get("dnssec") or "").lower() == "unsigned":
        out.append(_obs(domain, "infrastructure", "dnssec: unsigned",
                        f"The DNS zone of {domain} is not signed with DNSSEC.",
                        "DNS zone without DNSSEC signatures"))
    return out


EXTRACTORS = (email_auth, registration, reputation, subdomains, wayback,
              http_fingerprint, infrastructure)


def main() -> int:
    observations: list[dict] = []
    seen: set[str] = set()
    for domain_dir in sorted(p for p in FIXTURES.iterdir() if p.is_dir()):
        domain = domain_dir.name
        for extract in EXTRACTORS:
            for obs in extract(domain, domain_dir):
                # The same generic finding on several domains (e.g. "dmarc:
                # none") is one query: keep its first occurrence only.
                key = obs["phrasings"]["terse"]
                if key in seen:
                    continue
                seen.add(key)
                observations.append(obs)
    for i, obs in enumerate(observations, start=1):
        obs["id"] = f"obs-{i:03d}"
    OBSERVATIONS.write_text(
        json.dumps(
            {
                "_about": (
                    "Findings extracted by deterministic rules from evals/fixtures "
                    "(evals/rag/extract_observations.py) — no model wrote them. "
                    "Labels are assigned separately by two independent labelers."
                ),
                "observations": [{"id": o.pop("id"), **o} for o in observations],
            },
            ensure_ascii=False,
            indent=1,
        )
        + "\n",
        encoding="utf-8",
    )
    by_cat: dict[str, int] = {}
    for o in observations:
        by_cat[o["category"]] = by_cat.get(o["category"], 0) + 1
    print(f"{len(observations)} observations -> {OBSERVATIONS}: {by_cat}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
