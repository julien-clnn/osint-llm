"""WHOIS tool — domain registration information.

PASSIVE reconnaissance: the query goes to the registries' WHOIS servers
(public third parties), never to the target domain itself.
"""

from __future__ import annotations

import re
from typing import Any

import whois  # python-whois

from .base import Tool, cap_text

# Lightweight domain name validation (alphanumeric + hyphen labels, a TLD).
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def _normalize_domain(domain: str) -> str:
    """Clean user input into a bare domain name.

    Strips any scheme (http://), path, www. prefix, etc.
    """
    d = domain.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)  # strip http:// / https://
    d = d.split("/")[0]  # strip the path
    d = d.split("@")[-1]  # strip any user@
    d = d.split(":")[0]  # strip a port
    if d.startswith("www."):
        d = d[4:]
    return d


def _as_list(value: Any) -> list[str] | None:
    """Normalize fields that may be scalars, lists or None."""
    if value is None:
        return None
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _as_iso(value: Any) -> Any:
    """Serialize dates / lists of dates to ISO strings."""
    if isinstance(value, list):
        return [_as_iso(v) for v in value]
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


def whois_lookup(domain: str) -> dict[str, Any]:
    """Query a domain's WHOIS and return a useful subset.

    Args:
        domain: the domain name to query (e.g. "example.com").

    Returns:
        A dict with the registration fields, or {"error": ...}.
    """
    clean = _normalize_domain(domain)
    if not _DOMAIN_RE.match(clean):
        return {"error": f"Invalid domain name: {domain!r}"}

    record = whois.whois(clean)

    # python-whois returns an empty-ish dict when the domain is not found.
    if not record or record.get("domain_name") is None:
        return {
            "domain": clean,
            "found": False,
            "note": "No WHOIS record found (domain available or TLD not supported).",
        }

    return {
        "domain": clean,
        "found": True,
        "registrar": cap_text(record.get("registrar")),
        "creation_date": _as_iso(record.get("creation_date")),
        "expiration_date": _as_iso(record.get("expiration_date")),
        "updated_date": _as_iso(record.get("updated_date")),
        "name_servers": _as_list(record.get("name_servers")),
        "status": _as_list(record.get("status")),
        "registrant_org": cap_text(record.get("org")),
        "registrant_country": cap_text(record.get("country")),
        "emails": _as_list(record.get("emails")),
        "dnssec": record.get("dnssec"),
    }


whois_tool = Tool(
    name="whois_lookup",
    description=(
        "Fetches the WHOIS registration details of a domain name: "
        "registrar, creation/expiration dates, name servers, status, "
        "registrant organization and country. Passive reconnaissance."
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
    func=whois_lookup,
)
