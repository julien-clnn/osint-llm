"""Wayback Machine tool — archive history of a domain (CDX API).

Queries the free public CDX API of web.archive.org to list what has
historically been archived under a domain: subdomains (including old,
now-abandoned ones), notable URLs, and the time window covered.

Useful to find forgotten subdomains, old sensitive paths (admin, backups,
.git…) or to date the first/last known capture.

PASSIVE reconnaissance: we query the archive (public third party), never the
target domain.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from typing import Any

import requests

from ..http import get_json
from .base import Tool
from .whois_tool import _DOMAIN_RE, _normalize_domain

# CDX API: matchType=domain covers the domain AND all its subdomains.
_CDX_URL = "http://web.archive.org/cdx/search/cdx"
_HOST = "web.archive.org"

# Caps on what is returned to the LLM (a large site has millions of captures).
_MAX_SUBDOMAINS = 100
_MAX_URLS = 40
# Cap on rows requested from the API (collapse=urlkey already dedupes server-side).
_CDX_LIMIT = 10_000

# "Interesting" paths surfaced first (hints of past exposure).
_INTERESTING = (
    "admin",
    "login",
    "backup",
    "config",
    ".git",
    ".env",
    "wp-admin",
    "phpmyadmin",
    "api",
    "dev",
    "staging",
    "test",
    "old",
    "db",
    "dump",
    "sql",
)


def _ts_to_iso(ts: str) -> str:
    """Convert a CDX timestamp (YYYYMMDDhhmmss) to a readable ISO date."""
    if len(ts) >= 8 and ts.isdigit():
        return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"
    return ts


def wayback_lookup(domain: str) -> dict[str, Any]:
    """List a domain's historical footprint in the Wayback Machine.

    Args:
        domain: the root domain, e.g. "example.com".

    Returns:
        A dict with the archived subdomains, a sample of URLs (including
        notable paths), the date range covered, or {"error": ...}.
    """
    clean = _normalize_domain(domain)
    if not _DOMAIN_RE.match(clean):
        return {"error": f"Invalid domain name: {domain!r}"}

    try:
        rows = get_json(
            _CDX_URL,
            host=_HOST,
            params={
                "url": clean,
                "matchType": "domain",
                "output": "json",
                "fl": "original,timestamp",
                "collapse": "urlkey",
                "limit": _CDX_LIMIT,
            },
            timeout=30.0,
        )
    except (requests.RequestException, ValueError) as exc:
        return {"error": f"Wayback Machine unreachable: {exc}"}

    # The first row is the header (["original", "timestamp"]); the rest is data.
    if not isinstance(rows, list) or len(rows) <= 1:
        return {
            "domain": clean,
            "capture_count": 0,
            "subdomains": [],
            "interesting_urls": [],
            "sample_urls": [],
            "note": "No archived capture found for this domain.",
            "source": _HOST,
        }

    data_rows = rows[1:]
    subdomains: set[str] = set()
    interesting: list[dict[str, str]] = []
    sample: list[str] = []
    timestamps: list[str] = []

    for row in data_rows:
        if not row:
            continue
        original = row[0]
        ts = row[1] if len(row) > 1 else ""
        if ts:
            timestamps.append(ts)

        parts = urlsplit(original if "://" in original else f"http://{original}")
        host = parts.netloc.split("@")[-1].split(":")[0].lower()
        # The domain itself or a real subdomain (excludes "notexample.com",
        # which also ends with "example.com" without being a subdomain).
        if host == clean or host.endswith("." + clean):
            subdomains.add(host)

        low = original.lower()
        if len(interesting) < _MAX_URLS and any(k in low for k in _INTERESTING):
            interesting.append({"url": original, "timestamp": _ts_to_iso(ts)})
        elif len(sample) < _MAX_URLS:
            sample.append(original)

    ordered_subs = sorted(subdomains)
    date_range = None
    if timestamps:
        date_range = {
            "first": _ts_to_iso(min(timestamps)),
            "last": _ts_to_iso(max(timestamps)),
        }

    return {
        "domain": clean,
        "capture_count": len(data_rows),
        "truncated": len(data_rows) >= _CDX_LIMIT,
        "date_range": date_range,
        "subdomain_count": len(ordered_subs),
        "subdomains": ordered_subs[:_MAX_SUBDOMAINS],
        "interesting_urls": interesting,
        "sample_urls": sample[:_MAX_URLS],
        "source": _HOST,
    }


wayback_tool = Tool(
    name="wayback_lookup",
    description=(
        "Queries the Wayback Machine (web.archive.org, CDX API) to list what "
        "has historically been archived under a domain: subdomains (including "
        "old, abandoned ones), notable URLs (admin, backups, .git, .env…) and "
        "the date range of captures. Useful to find forgotten infrastructure. "
        "Passive reconnaissance (queries the archive, not the target)."
    ),
    parameters={
        "type": "object",
        "properties": {
            "domain": {
                "type": "string",
                "description": "The root domain to query, e.g. 'example.com'.",
            }
        },
        "required": ["domain"],
    },
    func=wayback_lookup,
)
