"""Subdomain enumeration tool based on Certificate Transparency.

TLS Certificate Transparency logs publicly list the names a certificate was
issued for — which, in practice, means subdomains.

Several free third-party sources (no key) are queried, each falling back to
the next, since any of them may be temporarily unavailable:
  1. crt.sh          (primary source, but notoriously unstable)
  2. certspotter     (fallback — SSLMate, same CT data, JSON response)

PASSIVE reconnaissance: we query these aggregators, never the target domain.
"""

from __future__ import annotations

import time
from typing import Any, Callable

import requests

from ..http import get_json
from .base import Tool
from .whois_tool import _DOMAIN_RE, _normalize_domain

# Cap on subdomains returned to the LLM (some domains have thousands).
_MAX_SUBDOMAINS = 100

# crt.sh is notoriously unstable (502s / timeouts), so retry a few times.
_MAX_RETRIES = 3
_RETRY_BACKOFF_S = 2.0


def _clean_names(raw_names: list[str], root: str) -> set[str]:
    """Normalize a raw list of names into valid subdomains of root."""
    names: set[str] = set()
    for raw in raw_names:
        for name in str(raw).splitlines():
            name = name.strip().lower().lstrip("*.")
            if name.endswith(root) and _DOMAIN_RE.match(name):
                names.add(name)
    return names


def _fetch_crtsh(root: str) -> set[str]:
    """Primary source: crt.sh. Raises on failure after retries."""
    last_exc: Exception | None = None
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            rows = get_json(
                "https://crt.sh/",
                host="crt.sh",
                params={"q": f"%.{root}", "output": "json"},
                timeout=30.0,
            )
            if not isinstance(rows, list):
                raise ValueError("unexpected crt.sh format")
            return _clean_names([r.get("name_value", "") for r in rows], root)
        except (requests.RequestException, ValueError) as exc:
            last_exc = exc
            if attempt < _MAX_RETRIES:
                time.sleep(_RETRY_BACKOFF_S * attempt)
    raise RuntimeError(f"crt.sh unreachable: {last_exc}")


def _fetch_certspotter(root: str) -> set[str]:
    """Fallback: certspotter (SSLMate). Raises on failure."""
    rows = get_json(
        "https://api.certspotter.com/v1/issuances",
        host="certspotter",
        params={
            "domain": root,
            "include_subdomains": "true",
            "expand": "dns_names",
        },
        timeout=30.0,
    )
    if not isinstance(rows, list):
        raise ValueError("unexpected certspotter format")
    raw: list[str] = []
    for row in rows:
        raw.extend(row.get("dns_names", []))
    return _clean_names(raw, root)


# Sources tried in order; (display name, function).
_PROVIDERS: list[tuple[str, Callable[[str], set[str]]]] = [
    ("crt.sh", _fetch_crtsh),
    ("certspotter", _fetch_certspotter),
]


def enumerate_subdomains(domain: str) -> dict[str, Any]:
    """List the known subdomains of a domain from CT logs.

    Tries each source in order and stops at the first one that answers.

    Args:
        domain: the root domain, e.g. "example.com".

    Returns:
        A dict with the deduplicated list of subdomains, or {"error": ...}.
    """
    clean = _normalize_domain(domain)
    if not _DOMAIN_RE.match(clean):
        return {"error": f"Invalid domain name: {domain!r}"}

    errors: list[str] = []
    for source_name, fetch in _PROVIDERS:
        try:
            names = fetch(clean)
        except Exception as exc:  # noqa: BLE001 — fall through to the next source
            errors.append(f"{source_name}: {exc}")
            continue

        ordered = sorted(names)
        return {
            "domain": clean,
            "subdomain_count": len(ordered),
            "subdomains": ordered[:_MAX_SUBDOMAINS],
            "truncated": len(ordered) > _MAX_SUBDOMAINS,
            "source": source_name,
        }

    return {"error": "All CT sources failed. " + " | ".join(errors)}


crtsh_tool = Tool(
    name="enumerate_subdomains",
    description=(
        "Enumerates a domain's subdomains from Certificate Transparency logs "
        "(crt.sh, falling back to certspotter). Useful to map the exposed "
        "attack surface. Passive reconnaissance."
    ),
    parameters={
        "type": "object",
        "properties": {
            "domain": {
                "type": "string",
                "description": "The root domain to enumerate, e.g. 'example.com'.",
            }
        },
        "required": ["domain"],
    },
    func=enumerate_subdomains,
)
