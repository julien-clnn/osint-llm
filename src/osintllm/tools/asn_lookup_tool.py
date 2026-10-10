"""ASN / IP range mapping tool.

The existing geolocation tool only sees a single IP. This one takes a step
back: from an IP, it finds the ASN (the autonomous system of the organization
announcing it), then every range (CIDR prefix) registered for that ASN — i.e.
the actual extent of the organization's network infrastructure, not just one
point.

Several free third-party sources (no key) are queried, each falling back to
the next — bgpview.io is notoriously unstable:
  1. bgpview.io   (rich data: description, country)
  2. RIPEstat     (RIPE NCC — very reliable, robust fallback)

PASSIVE reconnaissance: we query these aggregators, never the target's
infrastructure.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Callable

import requests

from ..http import get_json
from .base import Tool, cap_text

# Cap on prefixes returned to the LLM (a large carrier announces thousands).
_MAX_PREFIXES = 50


# --------------------------- Source 1 : bgpview.io ---------------------------

def _bgpview_most_specific_asn(prefixes: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Pick the ASN of the most specific prefix (longest mask)."""
    best: dict[str, Any] | None = None
    best_len = -1
    for entry in prefixes:
        cidr = entry.get("cidr")
        asn = entry.get("asn") or {}
        if not isinstance(cidr, int) or not asn.get("asn"):
            continue
        if cidr > best_len:
            best_len = cidr
            best = asn
    return best


def _lookup_bgpview(ip: str) -> dict[str, Any]:
    """Primary source: bgpview.io. Raises on failure."""
    data = get_json(f"https://api.bgpview.io/ip/{ip}", host="api.bgpview.io")
    if data.get("status") != "ok":
        raise ValueError("bgpview rejected the request")

    payload = data.get("data", {}) or {}
    prefixes = payload.get("prefixes", []) or []
    asn = _bgpview_most_specific_asn(prefixes)
    if asn is None:
        raise ValueError("no ASN announcing this IP")

    asn_number = asn.get("asn")
    announced = next(
        (p.get("prefix") for p in prefixes if (p.get("asn") or {}).get("asn") == asn_number),
        None,
    )

    pdata = get_json(
        f"https://api.bgpview.io/asn/{int(asn_number)}/prefixes", host="api.bgpview.io"
    )
    ipv4 = pdata.get("data", {}).get("ipv4_prefixes", []) if pdata.get("status") == "ok" else []
    all_prefixes = [
        {
            "prefix": p.get("prefix"),
            "name": p.get("name") or "",
            "country": p.get("country_code") or "",
        }
        for p in ipv4
    ]

    return _build(
        ip=ip,
        asn=asn_number,
        name=asn.get("name") or "",
        description=asn.get("description") or "",
        country=asn.get("country_code") or "",
        announced=announced,
        prefixes=all_prefixes,
        source="bgpview.io",
    )


# --------------------------- Source 2 : RIPEstat ---------------------------

def _lookup_ripestat(ip: str) -> dict[str, Any]:
    """Fallback: RIPEstat (RIPE NCC). Raises on failure."""
    overview = get_json(
        "https://stat.ripe.net/data/prefix-overview/data.json",
        host="stat.ripe.net",
        params={"resource": ip},
    )
    data = overview.get("data", {}) or {}
    asns = data.get("asns", []) or []
    if not asns:
        raise ValueError("no ASN announcing this IP")

    asn_number = asns[0].get("asn")
    holder = asns[0].get("holder") or ""
    announced = data.get("resource")

    prefixes_resp = get_json(
        "https://stat.ripe.net/data/announced-prefixes/data.json",
        host="stat.ripe.net",
        params={"resource": f"AS{asn_number}"},
    )
    rows = prefixes_resp.get("data", {}).get("prefixes", []) or []
    all_prefixes = [{"prefix": r.get("prefix"), "name": holder, "country": ""} for r in rows]

    return _build(
        ip=ip,
        asn=asn_number,
        name=holder,
        description=holder,
        country="",
        announced=announced,
        prefixes=all_prefixes,
        source="RIPEstat",
    )


# --------------------------- Shared ---------------------------

def _build(
    *,
    ip: str,
    asn: Any,
    name: str,
    description: str,
    country: str,
    announced: Any,
    prefixes: list[dict[str, Any]],
    source: str,
) -> dict[str, Any]:
    """Build the normalized result (identical regardless of the source)."""
    total = len(prefixes)
    return {
        "ip": ip,
        "asn": asn,
        "asn_name": cap_text(name),
        "asn_description": cap_text(description),
        "country": country,
        "announced_prefix": announced,
        "asn_prefixes": prefixes[:_MAX_PREFIXES],
        "prefix_count": total,
        "truncated": total > _MAX_PREFIXES,
        "source": source,
    }


# Sources tried in order; (display name, function).
_PROVIDERS: list[tuple[str, Callable[[str], dict[str, Any]]]] = [
    ("bgpview.io", _lookup_bgpview),
    ("RIPEstat", _lookup_ripestat),
]


def asn_lookup(ip: str) -> dict[str, Any]:
    """Find the ASN of an IP and every IP range of the owning organization.

    Tries each source in order and stops at the first one that answers.

    Args:
        ip: an IP address, e.g. "185.221.181.133".

    Returns:
        A dict with the ASN, the organization and its CIDR prefixes, or {"error": ...}.
    """
    clean = ip.strip()
    try:
        ipaddress.ip_address(clean)
    except ValueError:
        return {"error": f"Invalid IP address: {ip!r}"}

    errors: list[str] = []
    for source_name, lookup in _PROVIDERS:
        try:
            return lookup(clean)
        except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
            errors.append(f"{source_name}: {exc}")
            continue

    return {"error": "All ASN sources failed. " + " | ".join(errors)}


asn_lookup_tool = Tool(
    name="asn_lookup",
    description=(
        "From an IP, finds the ASN (autonomous system) of the organization "
        "announcing it and every IP range (CIDR prefix) registered for that "
        "ASN — the organization's network footprint, not just one IP. "
        "Useful after ip_geolocate. Passive reconnaissance (bgpview.io, RIPEstat)."
    ),
    parameters={
        "type": "object",
        "properties": {
            "ip": {
                "type": "string",
                "description": "An IP address, e.g. '185.221.181.133'.",
            }
        },
        "required": ["ip"],
    },
    func=asn_lookup,
)
