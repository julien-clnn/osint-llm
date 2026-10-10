"""Shared HTTP client for tools that query third-party sources.

Centralizes the User-Agent, the timeout and a small courtesy delay between
requests to the same host (crt.sh and ip-api.com enforce limits).
"""

from __future__ import annotations

import os
import random
import time
from contextvars import ContextVar
from typing import Any

import requests

USER_AGENT = "osintllm/0.1 (passive OSINT research; +https://github.com/)"
DEFAULT_TIMEOUT = 20.0

# Default proxy = SOCKS port of the local Tor daemon (`brew install tor` then `tor`).
# `socks5h`: DNS resolution ALSO goes through the proxy (the target domain
# does not leak). Tor Browser listens on port 9150 instead.
DEFAULT_PROXY_URL = "socks5h://127.0.0.1:9050"

# Pool of real browser User-Agents. Used ONLY for requests that contact the
# target directly (active mode: tech_fingerprint): we don't announce
# "osintllm" and vary the fingerprint from one call to the next to blend into
# ordinary browser traffic. Calls to passive third-party APIs keep the honest
# `USER_AGENT` above. Refresh from time to time.
_BROWSER_USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) "
    "Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) "
    "Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
)


def random_browser_user_agent() -> str:
    """Randomly chosen real browser User-Agent.

    Use it for requests that contact the target DIRECTLY (active mode), so
    the request is not signed "osintllm" and the fingerprint varies.
    """
    return random.choice(_BROWSER_USER_AGENTS)


# Per-request override (API worker thread): takes precedence over the env so
# concurrent analyses never see each other's proxy setting.
_proxy_override: ContextVar[bool | None] = ContextVar("_proxy_override", default=None)


def set_proxy_override(enabled: bool | None) -> None:
    """Force the proxy on/off for the current thread/context (None = use env)."""
    _proxy_override.set(enabled)


def proxy_enabled() -> bool:
    """True if requests to the target must go through a proxy.

    Per-context override first (see `set_proxy_override`, used by the API),
    then the env (`OSINTLLM_USE_PROXY=1`, used by the CLI).
    """
    override = _proxy_override.get()
    if override is not None:
        return override
    return os.getenv("OSINTLLM_USE_PROXY", "").lower() in ("1", "true", "yes")


def proxy_url() -> str:
    """Proxy URL to use (Tor by default), overridable via the env."""
    return os.getenv("OSINTLLM_PROXY_URL", DEFAULT_PROXY_URL).strip() or DEFAULT_PROXY_URL


def _proxies() -> dict[str, str] | None:
    """`proxies` dict for requests, or None when the proxy is disabled."""
    if not proxy_enabled():
        return None
    url = proxy_url()
    return {"http": url, "https": url}

# Minimum delay between two requests to the same host (courtesy / anti-ban).
_MIN_INTERVAL_S = 1.0
_last_call: dict[str, float] = {}

_session = requests.Session()
_session.headers.update({"User-Agent": USER_AGENT})


def _throttle(host: str) -> None:
    """Space out calls to the same host by at least _MIN_INTERVAL_S."""
    now = time.monotonic()
    last = _last_call.get(host)
    if last is not None:
        wait = _MIN_INTERVAL_S - (now - last)
        if wait > 0:
            time.sleep(wait)
    _last_call[host] = time.monotonic()


def throttle(host: str) -> None:
    """Public throttling, for tools that don't use requests (e.g. DNS).

    Applies the same per-host spacing as get_json/get_response, so tools built
    on other transports (dnspython…) stay just as polite.
    """
    _throttle(host)


def get_response(url: str, host: str, **kwargs: Any) -> requests.Response:
    """GET a URL and return the raw Response (headers, status…).

    Useful when the response headers are needed rather than the JSON body
    (e.g. tech_fingerprint, which reads Server/CSP/HSTS). The body is NOT read
    here; the caller passes `stream=True` to avoid downloading it.

    Args:
        url: the URL to query.
        host: logical host key, for throttling.
        **kwargs: passed to requests (headers, timeout, allow_redirects…).

    When the proxy is enabled (`OSINTLLM_USE_PROXY=1`), the request is routed
    through it (Tor by default): the target sees the proxy's IP, not ours.
    This is the ONLY path that contacts the target; passive third-party APIs
    (get_json) stay direct.

    Raises requests.RequestException on network failure; the calling tool is
    responsible for converting it into a clean error dict. `raise_for_status`
    is NOT called (a 4xx/5xx is still a usable response for fingerprinting).
    """
    _throttle(host)
    kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
    proxies = _proxies()
    if proxies is not None:
        kwargs.setdefault("proxies", proxies)
    return _session.get(url, **kwargs)


def get_json(url: str, host: str, **kwargs: Any) -> Any:
    """GET a URL and return the decoded JSON.

    Args:
        url: the URL to query.
        host: logical host key, for throttling (e.g. "crt.sh").
        **kwargs: passed to requests (params, timeout…).

    Raises requests.RequestException / ValueError on failure; the calling
    tool is responsible for converting them into a clean error dict.
    """
    _throttle(host)
    kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
    response = _session.get(url, **kwargs)
    response.raise_for_status()
    return response.json()
