"""DNS records tool — MX, TXT, NS + email posture (SPF / DMARC).

For a domain, fetches:
  - MX records (mail provider),
  - NS records (name servers — DNS host),
  - TXT records of the root domain, from which SPF presence is extracted,
  - the `_dmarc.<domain>` TXT record, from which DMARC presence/policy is extracted.

From these we derive an **email posture**: whether SPF and DMARC are present —
a simple but telling signal of the domain's anti-spoofing hardening.

Note on DKIM: a DKIM key lives under `<selector>._domainkey.<domain>` and the
selector cannot be enumerated blindly, so its absence cannot be asserted. We
only probe a handful of common selectors as a hint, without drawing any
negative conclusion.

Note on passivity: we do not query the target domain but the configured DNS
resolver; down the chain, it may reach the target's authoritative name
servers — the same "passive OSINT" limit as geolocation, explicitly accepted.
"""

from __future__ import annotations

from typing import Any

import dns.exception
import dns.resolver

from ..http import throttle
from .base import Tool, cap_text
from .whois_tool import _DOMAIN_RE, _normalize_domain

# Safety caps (some domains stack many TXT/NS entries).
_MAX_TXT = 30
_MAX_MX = 20
_MAX_NS = 20

# Short timeout: the system resolver answers quickly or not at all.
_DNS_TIMEOUT = 8.0

# Most common DKIM selectors (Google, Microsoft, generic, ESPs).
_DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "dkim", "mail")


def _resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = _DNS_TIMEOUT
    resolver.timeout = _DNS_TIMEOUT
    return resolver


def _query(resolver: dns.resolver.Resolver, name: str, rdtype: str) -> list[str]:
    """Query one record type; return [] if absent, raise otherwise.

    NXDOMAIN / NoAnswer / NoNameservers are not errors for us: they just mean
    "no record of this type", which is information in itself (e.g. no SPF).
    They are therefore mapped to an empty list.
    """
    try:
        answers = resolver.resolve(name, rdtype)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return []
    return [rr.to_text() for rr in answers]


def _txt_values(raw: list[str]) -> list[str]:
    """Normalize TXT values: dnspython returns them quoted, sometimes split."""
    values: list[str] = []
    for entry in raw:
        # A TXT record may be split into several "..." "..." strings to rejoin.
        parts = entry.split('" "')
        joined = "".join(p.strip('"') for p in parts) if len(parts) > 1 else entry.strip('"')
        values.append(joined)
    return values


def dns_records_lookup(domain: str) -> dict[str, Any]:
    """Fetch a domain's MX / TXT / NS records and derive its email posture.

    Args:
        domain: the domain name to query, e.g. "example.com".

    Returns:
        A dict with the records and an `email_security` block
        (whether spf/dmarc are present), or {"error": ...}.
    """
    clean = _normalize_domain(domain)
    if not _DOMAIN_RE.match(clean):
        return {"error": f"Invalid domain name: {domain!r}"}

    throttle("dns")
    resolver = _resolver()

    try:
        mx_raw = _query(resolver, clean, "MX")
        ns_raw = _query(resolver, clean, "NS")
        txt_raw = _txt_values(_query(resolver, clean, "TXT"))
        dmarc_raw = _txt_values(_query(resolver, f"_dmarc.{clean}", "TXT"))
    except dns.exception.DNSException as exc:
        return {"error": f"DNS resolution failed for {clean}: {exc}"}

    # MX sorted by priority (to_text() format is "<prio> <host>.").
    mx = sorted(m.rstrip(".") for m in mx_raw)[:_MAX_MX]
    ns = sorted(n.rstrip(".").lower() for n in ns_raw)[:_MAX_NS]
    # Third-party free text (the registrant writes whatever they want in their
    # DNS zone): capped per field, see docs/THREAT_MODEL.md.
    txt = [cap_text(t) for t in txt_raw[:_MAX_TXT]]

    spf = next((t for t in txt if t.lower().startswith("v=spf1")), None)
    dmarc = cap_text(next((d for d in dmarc_raw if d.lower().startswith("v=dmarc1")), None))
    dmarc_policy = None
    if dmarc:
        for token in dmarc.split(";"):
            token = token.strip()
            if token.lower().startswith("p="):
                dmarc_policy = token[2:].strip().lower()
                break

    # DKIM: just a hint (common selectors), never a negative conclusion.
    dkim_selectors_found = [
        sel
        for sel in _DKIM_SELECTORS
        if _query(resolver, f"{sel}._domainkey.{clean}", "TXT")
    ]

    return {
        "domain": clean,
        "mx": mx,
        "mx_count": len(mx_raw),
        "ns": ns,
        "ns_count": len(ns_raw),
        "txt": txt,
        "txt_count": len(txt_raw),
        "email_security": {
            "spf": spf is not None,
            "spf_record": spf,
            "dmarc": dmarc is not None,
            "dmarc_policy": dmarc_policy,
            "dkim_selectors_found": dkim_selectors_found,
            # DKIM is inconclusive: only common selectors are probed.
            "dkim_note": (
                "Only common DKIM selectors were probed; absence here does "
                "not prove that DKIM is missing."
            ),
        },
        "source": "DNS (system resolver)",
    }


dns_records_tool = Tool(
    name="dns_records_lookup",
    description=(
        "Fetches a domain's MX, TXT and NS DNS records and derives its email "
        "posture: presence of SPF (TXT v=spf1), DMARC (_dmarc, with its p= "
        "policy), and DKIM hints. Useful to identify the mail provider, the DNS "
        "host and anti-spoofing hardening. "
        "Passive reconnaissance (third-party DNS resolver)."
    ),
    parameters={
        "type": "object",
        "properties": {
            "domain": {
                "type": "string",
                "description": "The domain name to query, e.g. 'example.com'.",
            }
        },
        "required": ["domain"],
    },
    func=dns_records_lookup,
)
