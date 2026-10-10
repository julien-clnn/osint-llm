"""Technology fingerprinting tool — HTTP headers of the home page.

⚠️ The ONLY tool in the project that touches the target's infrastructure: it
sends **a single** lightweight HTTP GET request (headers only, body not
downloaded) to the domain's home page — no crawling, no scanning. It is
deliberately a minimal fingerprint, on the edge of "passive", as opposed to an
active scan.

Response headers are analyzed to infer:
  - the likely tech stack (Server, X-Powered-By, cookies, generators);
  - the hardening level of the security headers (CSP, HSTS, X-Frame-Options,
    X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any
from urllib.parse import urljoin, urlsplit

import requests

from ..http import (
    get_response,
    proxy_enabled,
    proxy_url,
    random_browser_user_agent,
)
from .whois_tool import _DOMAIN_RE, _normalize_domain
from .base import Tool

# Security headers expected on a hardened site (HTTP header -> display name).
_SECURITY_HEADERS = {
    "content-security-policy": "CSP",
    "strict-transport-security": "HSTS",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}

# Tech hints recognizable in some headers (substring -> technology).
_TECH_HINTS = {
    "cloudflare": "Cloudflare (CDN/WAF)",
    "nginx": "nginx",
    "apache": "Apache",
    "microsoft-iis": "Microsoft IIS",
    "litespeed": "LiteSpeed",
    "openresty": "OpenResty",
    "wordpress": "WordPress",
    "php": "PHP",
    "asp.net": "ASP.NET",
    "express": "Express (Node.js)",
    "next.js": "Next.js",
    "vercel": "Vercel",
    "gunicorn": "Gunicorn (Python)",
    "wp-": "WordPress",
    "laravel": "Laravel",
}


def _guess_tech(headers: dict[str, str]) -> list[str]:
    """Infer likely technologies from several revealing headers."""
    haystack = " ".join(
        headers.get(h, "")
        for h in ("server", "x-powered-by", "x-generator", "set-cookie", "via")
    ).lower()
    found: list[str] = []
    for needle, label in _TECH_HINTS.items():
        if needle in haystack and label not in found:
            found.append(label)
    return found


_MAX_REDIRECTS = 5


def _non_public_ip(host: str) -> str | None:
    """First non-public IP `host` resolves to (loopback, private, link-local…),
    or None. Resolution failures return None: the request then fails on its own."""
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        return None
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            return str(ip)
    return None


def _private_hostname(host: str) -> bool:
    """Best-effort check without DNS (behind the proxy): IP literal that is not
    public, or a name that only exists on a local network."""
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        name = host.lower().rstrip(".")
        return "." not in name or name.endswith((".localhost", ".local", ".internal", ".lan"))


def _fetch(url: str, headers: dict[str, str]) -> requests.Response:
    """GET `url`, following redirects manually so that every hop is checked
    against non-public addresses (SSRF guard). Skipped behind the proxy: DNS
    then goes through it and a local lookup would leak the target."""
    for _ in range(_MAX_REDIRECTS + 1):
        host = urlsplit(url).hostname or ""
        if proxy_enabled():
            if _private_hostname(host):
                raise requests.RequestException(f"refused: {host} is a non-public host")
        else:
            blocked = _non_public_ip(host)
            if blocked is not None:
                raise requests.RequestException(
                    f"refused: {host} resolves to a non-public address ({blocked})"
                )
        response = get_response(
            url,
            host=host,
            stream=True,
            allow_redirects=False,
            timeout=15.0,
            headers=headers,
        )
        location = response.headers.get("location") if 300 <= response.status_code < 400 else None
        if not location:
            return response
        response.close()
        url = urljoin(url, location)
    raise requests.TooManyRedirects(f"more than {_MAX_REDIRECTS} redirects")


def tech_fingerprint(domain: str) -> dict[str, Any]:
    """Tech fingerprint + header hardening of the home page.

    Sends ONE GET request (tries https, then http) and analyzes the headers.

    Args:
        domain: the domain to fingerprint, e.g. "example.com".

    Returns:
        A dict with the inferred tech, the present/missing security headers
        and a hardening score, or {"error": ...}.
    """
    clean = _normalize_domain(domain)
    if not _DOMAIN_RE.match(clean):
        return {"error": f"Invalid domain name: {domain!r}"}

    response = None
    scheme_used = None
    errors: list[str] = []
    # Random browser UA: this request hits the target, so it is not signed
    # "osintllm" and the fingerprint varies from one call to the next.
    browser_headers = {"User-Agent": random_browser_user_agent()}
    for scheme in ("https", "http"):
        try:
            # stream=True: read the headers without downloading the body (lightweight).
            response = _fetch(f"{scheme}://{clean}/", browser_headers)
            scheme_used = scheme
            break
        except requests.RequestException as exc:
            errors.append(f"{scheme}: {exc}")
            continue

    if response is None:
        if proxy_enabled():
            return {
                "error": (
                    f"Home page unreachable through the proxy ({proxy_url()}). "
                    "Is the proxy running (e.g. Tor daemon on "
                    "127.0.0.1:9050) and does the target accept this exit "
                    "node? Details: " + " | ".join(errors)
                )
            }
        return {"error": "Home page unreachable. " + " | ".join(errors)}

    try:
        # Headers are case-insensitive -> lowercase dict for analysis.
        headers = {k.lower(): v for k, v in response.headers.items()}
    finally:
        response.close()  # release the connection without reading the body

    present = {label: headers[h] for h, label in _SECURITY_HEADERS.items() if h in headers}
    missing = [label for h, label in _SECURITY_HEADERS.items() if h not in headers]
    score = len(present)
    total = len(_SECURITY_HEADERS)
    if score == total:
        posture = "strong"
    elif score >= total // 2:
        posture = "partial"
    else:
        posture = "weak"

    return {
        "domain": clean,
        "final_url": response.url,
        "scheme": scheme_used,
        "status_code": response.status_code,
        "server": headers.get("server"),
        "x_powered_by": headers.get("x-powered-by"),
        "detected_tech": _guess_tech(headers),
        "security_headers_present": present,
        "security_headers_missing": missing,
        "hardening_score": f"{score}/{total}",
        "hardening_posture": posture,
        "via_proxy": proxy_enabled(),
        "source": (
            "single HTTP request to the target (headers only, browser UA"
            + (", via proxy" if proxy_enabled() else "")
            + ")"
        ),
    }


tech_fingerprint_tool = Tool(
    name="tech_fingerprint",
    description=(
        "Sends ONE lightweight HTTP GET request (headers only, no crawling) to "
        "the domain's home page and analyzes the response headers to infer "
        "the likely tech stack (Server, X-Powered-By, cookies) and the "
        "hardening of security headers (CSP, HSTS, X-Frame-Options…). "
        "The only tool that touches the target — a single, deliberately "
        "minimal request. Reserved for ACTIVE reconnaissance."
    ),
    passive=False,
    parameters={
        "type": "object",
        "properties": {
            "domain": {
                "type": "string",
                "description": "The domain to fingerprint, e.g. 'example.com'.",
            }
        },
        "required": ["domain"],
    },
    func=tech_fingerprint,
)
