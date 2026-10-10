"""GitHub search tool based on the public Search API.

For a domain, queries the GitHub Search API (api.github.com) to find:
  1. public repositories mentioning the domain (name / description / README);
  2. if a token is provided, code files containing the domain — useful to
     spot secrets, API keys or configs committed by mistake.

Repository search works without authentication (rate limit ~10 req/min).
CODE search, however, requires a GitHub token (GITHUB_TOKEN env var); without
one it is cleanly skipped and flagged in the result.

PASSIVE reconnaissance: we query api.github.com (public third party), never
the target's infrastructure.
"""

from __future__ import annotations

import os
from typing import Any

import requests

from ..http import get_json
from .base import Tool
from .whois_tool import _DOMAIN_RE, _normalize_domain

_API = "https://api.github.com"
_HOST = "api.github.com"

# Caps on results returned to the LLM (avoids flooding the context).
_MAX_REPOS = 10
_MAX_CODE = 10
# Max length of a returned code snippet (GitHub fragments are short).
_MAX_SNIPPET = 300


def _headers(*, text_match: bool = False) -> dict[str, str]:
    """GitHub headers: API version, optional token, code snippets."""
    accept = (
        "application/vnd.github.text-match+json"
        if text_match
        else "application/vnd.github+json"
    )
    headers = {"Accept": accept, "X-GitHub-Api-Version": "2022-11-28"}
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _search_repositories(domain: str) -> list[dict[str, Any]]:
    """Public repositories mentioning the domain (no authentication required)."""
    data = get_json(
        f"{_API}/search/repositories",
        host=_HOST,
        params={"q": domain, "per_page": _MAX_REPOS, "sort": "stars"},
        headers=_headers(),
    )
    items = data.get("items", []) if isinstance(data, dict) else []
    repos: list[dict[str, Any]] = []
    for item in items[:_MAX_REPOS]:
        repos.append(
            {
                "repo": item.get("full_name"),
                "url": item.get("html_url"),
                # Some repositories abuse this field for SEO/spam (observed:
                # a 241,893-character description in a real-world case).
                # Same cap as `snippet` below, for the same reason.
                "description": (item.get("description") or "")[:_MAX_SNIPPET],
                "stars": item.get("stargazers_count", 0),
            }
        )
    return repos


def _first_snippet(item: dict[str, Any]) -> str:
    """Extract the first code fragment returned by the API (text-match)."""
    for match in item.get("text_matches", []) or []:
        fragment = (match.get("fragment") or "").strip()
        if fragment:
            return fragment[:_MAX_SNIPPET]
    return ""


def _search_code(domain: str) -> list[dict[str, Any]]:
    """Code files containing the domain (requires a GitHub token)."""
    data = get_json(
        f"{_API}/search/code",
        host=_HOST,
        params={"q": f'"{domain}"', "per_page": _MAX_CODE},
        headers=_headers(text_match=True),
    )
    items = data.get("items", []) if isinstance(data, dict) else []
    matches: list[dict[str, Any]] = []
    for item in items[:_MAX_CODE]:
        repo = item.get("repository", {}) or {}
        matches.append(
            {
                "repo": repo.get("full_name"),
                "url": item.get("html_url"),
                "path": item.get("path"),
                "snippet": _first_snippet(item),
            }
        )
    return matches


def _rate_limit_message(exc: requests.HTTPError) -> str | None:
    """Clear message if the error is a GitHub rate-limit hit, otherwise None."""
    resp = exc.response
    if resp is None:
        return None
    if resp.status_code in (403, 429) and resp.headers.get("X-RateLimit-Remaining") == "0":
        return (
            "GitHub rate limit reached (unauthenticated). Retry later or "
            "set GITHUB_TOKEN for a higher quota."
        )
    return None


def github_search(domain: str) -> dict[str, Any]:
    """Search GitHub for repositories and code mentioning a domain.

    Args:
        domain: the domain (or subdomain) to search for, e.g. "example.com".

    Returns:
        A dict with the repositories found, the code matches (if a token is
        configured), or {"error": ...}.
    """
    clean = _normalize_domain(domain)
    if not _DOMAIN_RE.match(clean):
        return {"error": f"Invalid domain name: {domain!r}"}

    token_present = bool(os.getenv("GITHUB_TOKEN", "").strip())

    try:
        repos = _search_repositories(clean)
    except requests.HTTPError as exc:
        msg = _rate_limit_message(exc)
        return {"error": msg or f"GitHub repository search failed: {exc}"}
    except (requests.RequestException, ValueError) as exc:
        return {"error": f"GitHub repository search failed: {exc}"}

    result: dict[str, Any] = {
        "domain": clean,
        "repository_matches": repos,
        "repository_count": len(repos),
        "code_search_enabled": token_present,
        "code_matches": [],
        "source": _HOST,
    }

    # Code search requires a token: otherwise report it without failing.
    if not token_present:
        result["note"] = (
            "Code search disabled (set GITHUB_TOKEN to detect secrets/domains "
            "in public code)."
        )
        return result

    try:
        result["code_matches"] = _search_code(clean)
    except requests.HTTPError as exc:
        msg = _rate_limit_message(exc)
        result["code_search_error"] = msg or f"Code search failed: {exc}"
    except (requests.RequestException, ValueError) as exc:
        result["code_search_error"] = f"Code search failed: {exc}"

    return result


github_search_tool = Tool(
    name="github_search",
    description=(
        "Searches GitHub for public repositories and code mentioning a "
        "domain: repositories tied to the organization, secrets/API keys or "
        "configs committed by mistake. Pass the domain or a discovered "
        "subdomain. Passive reconnaissance (queries api.github.com, not the target)."
    ),
    parameters={
        "type": "object",
        "properties": {
            "domain": {
                "type": "string",
                "description": "The domain or subdomain to search for.",
            }
        },
        "required": ["domain"],
    },
    func=github_search,
)
