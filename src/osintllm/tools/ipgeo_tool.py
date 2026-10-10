"""IP geolocation tool based on ip-api.com.

Accepts a domain or an IP. For a domain, it is first resolved to IPv4
address(es) (DNS resolution), then each IP is geolocated via ip-api.com
(country, city, coordinates, network operator / AS).

Note on passivity: geolocation itself only queries ip-api.com (public third
party). DNS resolution goes through the configured resolver and may, down the
chain, reach the target's authoritative name servers — the usual limit of
"passive" OSINT, explicitly accepted here.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any

import requests

from ..http import get_json
from .base import Tool
from .whois_tool import _DOMAIN_RE, _normalize_domain

# Fields requested from ip-api (limits volume and documents what we fetch).
_IPAPI_FIELDS = "status,message,query,country,countryCode,regionName,city,lat,lon,isp,org,as"

# Cap on IPs geolocated per call (courtesy to ip-api: 45 req/min).
_MAX_IPS = 5


def _resolve_ipv4(host: str) -> list[str]:
    """Resolve a hostname to a list of unique IPv4 addresses."""
    infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
    return sorted({info[4][0] for info in infos})


def _geolocate_ip(ip: str) -> dict[str, Any]:
    """Query ip-api.com for a given IP."""
    data = get_json(
        f"http://ip-api.com/json/{ip}",
        host="ip-api.com",
        params={"fields": _IPAPI_FIELDS},
    )
    if data.get("status") != "success":
        return {"ip": ip, "error": data.get("message", "ip-api failure")}
    return {
        "ip": ip,
        "country": data.get("country"),
        "country_code": data.get("countryCode"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "lat": data.get("lat"),
        "lon": data.get("lon"),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "as": data.get("as"),
    }


def ip_geolocate(target: str) -> dict[str, Any]:
    """Geolocate a domain (after resolution) or an IP.

    Args:
        target: a domain ("example.com") or an IP address ("93.184.216.34").

    Returns:
        A dict with the geolocated IP(s), or {"error": ...}.
    """
    clean = _normalize_domain(target)

    # Case 1: it is already an IP address.
    try:
        ipaddress.ip_address(clean)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        ips = [clean]
        resolved_from = None
    else:
        if not _DOMAIN_RE.match(clean):
            return {"error": f"Invalid target (neither a domain nor an IP): {target!r}"}
        try:
            ips = _resolve_ipv4(clean)
        except socket.gaierror as exc:
            return {"error": f"DNS resolution failed for {clean}: {exc}"}
        if not ips:
            return {"error": f"No IPv4 address found for {clean}."}
        resolved_from = clean

    locations: list[dict[str, Any]] = []
    for ip in ips[:_MAX_IPS]:
        try:
            locations.append(_geolocate_ip(ip))
        except requests.RequestException as exc:
            locations.append({"ip": ip, "error": f"ip-api unreachable: {exc}"})
        except ValueError:
            locations.append({"ip": ip, "error": "Unreadable ip-api response."})

    return {
        "target": clean,
        "resolved_from_domain": resolved_from,
        "ip_count": len(ips),
        "locations": locations,
        "truncated": len(ips) > _MAX_IPS,
        "source": "ip-api.com",
    }


ipgeo_tool = Tool(
    name="ip_geolocate",
    description=(
        "Geolocates a domain or an IP: resolves the domain to IP(s), then "
        "returns country, city, coordinates and network operator (AS) via "
        "ip-api.com. Passive reconnaissance."
    ),
    parameters={
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "A domain ('example.com') or an IP address.",
            }
        },
        "required": ["target"],
    },
    func=ip_geolocate,
)
