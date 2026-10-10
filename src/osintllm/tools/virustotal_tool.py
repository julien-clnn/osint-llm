"""VirusTotal tool — domain reputation + passive DNS (free API v3).

Queries the public VirusTotal v3 API to fetch:
  1. the domain's reputation: aggregated engine verdicts (harmless /
     malicious / suspicious), reputation score, community votes,
     categories;
  2. passive DNS: IPs historically associated with the domain
     (`/resolutions` endpoint) — the infrastructure history as seen by VT.

Quota constraints (free tier: ~4 req/min, 500/day):
  - **Aggressive disk cache**: handled by the tool base (base.Tool.run,
    24 h TTL) — a second identical call consumes no quota. VirusTotal
    benefits from it the most.
  - **Clean fallback**: without a key (`VT_API_KEY`), the tool disables
    itself cleanly and says so, without failing. When the quota is exceeded
    (429), a clear message is returned instead of an exception.

PASSIVE reconnaissance: we query VirusTotal (public third party), never the target.
"""

from __future__ import annotations

import os
from typing import Any

import requests

from ..http import get_json
from .base import Tool
from .whois_tool import _DOMAIN_RE, _normalize_domain

_API = "https://www.virustotal.com/api/v3"
_HOST = "www.virustotal.com"

# Cap on passive DNS IPs returned to the LLM.
_MAX_RESOLUTIONS = 30


def _headers() -> dict[str, str]:
    return {"x-apikey": os.getenv("VT_API_KEY", "").strip(), "Accept": "application/json"}


def _quota_or_auth_message(exc: requests.HTTPError) -> str | None:
    """Clear message for VT quota / auth errors, otherwise None."""
    resp = exc.response
    if resp is None:
        return None
    if resp.status_code == 429:
        return (
            "VirusTotal quota exceeded (free tier ~4 req/min, 500/day). "
            "Retry later — the disk cache avoids consuming the quota again."
        )
    if resp.status_code == 401:
        return "VT_API_KEY is invalid or revoked (401)."
    if resp.status_code == 404:
        return None  # 404 = domain unknown to VT, handled separately
    return None


def _fetch_domain(domain: str) -> dict[str, Any]:
    """Domain reputation block (VT v3 attributes)."""
    data = get_json(f"{_API}/domains/{domain}", host=_HOST, headers=_headers())
    attrs = (data.get("data", {}) or {}).get("attributes", {}) or {}
    stats = attrs.get("last_analysis_stats", {}) or {}
    votes = attrs.get("total_votes", {}) or {}
    return {
        "reputation": attrs.get("reputation"),
        "last_analysis_stats": {
            "harmless": stats.get("harmless", 0),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
        },
        "malicious_votes": votes.get("malicious", 0),
        "harmless_votes": votes.get("harmless", 0),
        "categories": list((attrs.get("categories", {}) or {}).values())[:10],
    }


def _fetch_resolutions(domain: str) -> list[dict[str, Any]]:
    """Passive DNS: IPs historically associated with the domain."""
    data = get_json(
        f"{_API}/domains/{domain}/resolutions",
        host=_HOST,
        headers=_headers(),
        params={"limit": _MAX_RESOLUTIONS},
    )
    out: list[dict[str, Any]] = []
    for item in data.get("data", []) or []:
        attrs = item.get("attributes", {}) or {}
        out.append(
            {
                "ip_address": attrs.get("ip_address"),
                "last_resolved": attrs.get("date"),
            }
        )
    return out


def virustotal_lookup(domain: str) -> dict[str, Any]:
    """Domain reputation + passive DNS via VirusTotal.

    Args:
        domain: the domain to query, e.g. "example.com".

    Returns:
        A dict with the reputation, engine verdicts and passive DNS, or a
        clean disabled/error result (missing key, quota exceeded…).
    """
    clean = _normalize_domain(domain)
    if not _DOMAIN_RE.match(clean):
        return {"error": f"Invalid domain name: {domain!r}"}

    if not os.getenv("VT_API_KEY", "").strip():
        return {
            "domain": clean,
            "enabled": False,
            "note": (
                "VirusTotal disabled: set VT_API_KEY (free key at "
                "virustotal.com) for reputation and passive DNS."
            ),
            "source": _HOST,
        }

    # 1) Reputation (required) — a failure here means an error result.
    try:
        reputation = _fetch_domain(clean)
    except requests.HTTPError as exc:
        msg = _quota_or_auth_message(exc)
        if msg:
            return {"domain": clean, "enabled": True, "error": msg, "source": _HOST}
        if exc.response is not None and exc.response.status_code == 404:
            return {
                "domain": clean,
                "enabled": True,
                "found": False,
                "note": "Domain unknown to VirusTotal (no analysis on record).",
                "source": _HOST,
            }
        return {"domain": clean, "enabled": True, "error": f"VirusTotal: {exc}", "source": _HOST}
    except (requests.RequestException, ValueError) as exc:
        return {"domain": clean, "enabled": True, "error": f"VirusTotal: {exc}", "source": _HOST}

    result: dict[str, Any] = {
        "domain": clean,
        "enabled": True,
        "found": True,
        **reputation,
        "passive_dns": [],
        "source": _HOST,
    }

    # 2) Passive DNS (optional) — a failure (often quota) does not break the whole result.
    try:
        result["passive_dns"] = _fetch_resolutions(clean)
    except requests.HTTPError as exc:
        result["passive_dns_error"] = _quota_or_auth_message(exc) or f"passive DNS: {exc}"
    except (requests.RequestException, ValueError) as exc:
        result["passive_dns_error"] = f"passive DNS: {exc}"

    return result


virustotal_tool = Tool(
    name="virustotal_lookup",
    description=(
        "Queries VirusTotal (free API v3) for a domain's reputation "
        "(aggregated engine verdicts: harmless/malicious/suspicious, score, "
        "votes, categories) and passive DNS (historically associated IPs). "
        "Requires VT_API_KEY; without a key, disables itself cleanly. Low quota: "
        "results are cached. Passive reconnaissance (queries VT, not the target)."
    ),
    parameters={
        "type": "object",
        "properties": {
            "domain": {
                "type": "string",
                "description": "The domain to query, e.g. 'example.com'.",
            }
        },
        "required": ["domain"],
    },
    func=virustotal_lookup,
)
