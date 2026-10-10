"""Tests for the new passive tools: github_search and asn_lookup.

The network is mocked (`get_json` is replaced in each tool module): these
tests check result shaping, not API availability.
"""

from __future__ import annotations

import importlib

# Note: the Tool name (`asn_lookup_tool`) shadows the same-named submodule
# attribute on the package, so the real module is fetched via importlib.
asn_mod = importlib.import_module("osintllm.tools.asn_lookup_tool")
gh_mod = importlib.import_module("osintllm.tools.github_search_tool")


# --------------------------- github_search ---------------------------

def test_github_search_repos_without_token(monkeypatch):
    """Without GITHUB_TOKEN: repositories returned, code search disabled."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(
        gh_mod,
        "get_json",
        lambda *a, **k: {
            "items": [
                {
                    "full_name": "acme/site",
                    "html_url": "https://github.com/acme/site",
                    "description": "example.com website",
                    "stargazers_count": 12,
                }
            ]
        },
    )

    out = gh_mod.github_search("https://www.example.com/path")

    assert out["domain"] == "example.com"  # normalization applied
    assert out["repository_count"] == 1
    assert out["repository_matches"][0]["repo"] == "acme/site"
    assert out["code_search_enabled"] is False
    assert out["code_matches"] == []
    assert "note" in out


def test_github_search_invalid_domain():
    out = gh_mod.github_search("not a domain")
    assert "error" in out


# --------------------------- asn_lookup ---------------------------

def _fake_bgpview(url, host, **kwargs):
    """Router bgpview : /ip/<ip> puis /asn/<n>/prefixes."""
    if "/ip/" in url:
        return {
            "status": "ok",
            "data": {
                "prefixes": [
                    {
                        "prefix": "185.221.180.0/22",
                        "cidr": 22,
                        "asn": {
                            "asn": 53589,
                            "name": "PLANETHOSTER",
                            "description": "PlanetHoster Inc.",
                            "country_code": "CA",
                        },
                    }
                ]
            },
        }
    if "/prefixes" in url:
        return {
            "status": "ok",
            "data": {
                "ipv4_prefixes": [
                    {"prefix": "185.221.180.0/22", "name": "PH", "country_code": "FR"},
                    {"prefix": "167.114.0.0/17", "name": "PH", "country_code": "CA"},
                ]
            },
        }
    raise AssertionError(f"Unexpected URL: {url}")


def test_asn_lookup_enriches_ranges(monkeypatch):
    monkeypatch.setattr(asn_mod, "get_json", _fake_bgpview)

    out = asn_mod.asn_lookup("185.221.181.133")

    assert out["asn"] == 53589
    assert out["asn_name"] == "PLANETHOSTER"
    assert out["announced_prefix"] == "185.221.180.0/22"
    assert out["prefix_count"] == 2
    assert {p["prefix"] for p in out["asn_prefixes"]} == {
        "185.221.180.0/22",
        "167.114.0.0/17",
    }


def _fake_ripestat_only(url, host, **kwargs):
    """bgpview unreachable → must fall back to RIPEstat."""
    if "bgpview" in url:
        raise __import__("requests").exceptions.ConnectionError("bgpview down")
    if "prefix-overview" in url:
        return {"data": {"resource": "140.82.121.0/24",
                         "asns": [{"asn": 36459, "holder": "GITHUB - GitHub, Inc."}]}}
    if "announced-prefixes" in url:
        return {"data": {"prefixes": [
            {"prefix": "140.82.112.0/20"}, {"prefix": "140.82.121.0/24"},
        ]}}
    raise AssertionError(f"Unexpected URL: {url}")


def test_asn_lookup_ripestat_fallback(monkeypatch):
    """When bgpview fails, RIPEstat takes over."""
    monkeypatch.setattr(asn_mod, "get_json", _fake_ripestat_only)

    out = asn_mod.asn_lookup("140.82.121.4")

    assert out["asn"] == 36459
    assert out["source"] == "RIPEstat"
    assert out["asn_name"] == "GITHUB - GitHub, Inc."
    assert out["announced_prefix"] == "140.82.121.0/24"
    assert out["prefix_count"] == 2


def test_asn_lookup_invalid_ip():
    out = asn_mod.asn_lookup("999.999.0.1")
    assert "error" in out
