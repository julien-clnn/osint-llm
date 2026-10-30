"""Tests for the 4 reconnaissance tools added on D10:
dns_records_lookup, wayback_lookup, tech_fingerprint, virustotal_lookup.

The network / DNS resolver is mocked in each tool module: these tests check
result shaping and inference (posture, quotas), not the actual availability
of the sources.
"""

from __future__ import annotations

import importlib
from pathlib import Path

from osintllm import fixtures

dns_mod = importlib.import_module("osintllm.tools.dns_records_tool")
wb_mod = importlib.import_module("osintllm.tools.wayback_tool")
fp_mod = importlib.import_module("osintllm.tools.tech_fingerprint_tool")
vt_mod = importlib.import_module("osintllm.tools.virustotal_tool")


# --------------------------- dns_records_lookup ---------------------------

def test_dns_records_spf_dmarc(monkeypatch):
    """MX/NS/TXT normalized + SPF and DMARC (with policy) detected."""

    def fake_query(resolver, name, rdtype):
        if name == "example.com" and rdtype == "MX":
            return ["10 mail.example.com.", "20 mail2.example.com."]
        if name == "example.com" and rdtype == "NS":
            return ["ns1.example.com.", "ns2.example.com."]
        if name == "example.com" and rdtype == "TXT":
            return ['"v=spf1 include:_spf.google.com ~all"', '"google-site-verification=abc"']
        if name == "_dmarc.example.com" and rdtype == "TXT":
            return ['"v=DMARC1; p=reject; rua=mailto:d@example.com"']
        return []  # no DKIM on the probed selectors

    monkeypatch.setattr(dns_mod, "_query", fake_query)

    out = dns_mod.dns_records_lookup("https://www.example.com/path")

    assert out["domain"] == "example.com"  # normalization
    assert out["mx"] == ["10 mail.example.com", "20 mail2.example.com"]
    assert out["ns"] == ["ns1.example.com", "ns2.example.com"]
    sec = out["email_security"]
    assert sec["spf"] is True
    assert sec["spf_record"].startswith("v=spf1")
    assert sec["dmarc"] is True
    assert sec["dmarc_policy"] == "reject"
    assert sec["dkim_selectors_found"] == []


def test_dns_records_without_spf_or_dmarc(monkeypatch):
    """Missing SPF/DMARC → degraded email posture reported (False booleans)."""
    monkeypatch.setattr(dns_mod, "_query", lambda resolver, name, rdtype: [])

    out = dns_mod.dns_records_lookup("nowhere.test")

    assert out["email_security"]["spf"] is False
    assert out["email_security"]["dmarc"] is False
    assert out["email_security"]["dmarc_policy"] is None


def test_dns_records_invalid_domain():
    out = dns_mod.dns_records_lookup("not a domain")
    assert "error" in out


# --------------------------- wayback_lookup ---------------------------

def test_wayback_extracts_subdomains_and_urls(monkeypatch):
    """Extracts subdomains, notable URLs and the date range from CDX."""
    monkeypatch.setattr(
        wb_mod,
        "get_json",
        lambda *a, **k: [
            ["original", "timestamp"],
            ["http://example.com/", "20100615120000"],
            ["http://old.example.com/admin/login", "20150101000000"],
            ["http://www.example.com/index.html", "20200320090000"],
        ],
    )

    out = wb_mod.wayback_lookup("example.com")

    assert out["capture_count"] == 3
    assert "old.example.com" in out["subdomains"]
    assert out["date_range"] == {"first": "2010-06-15", "last": "2020-03-20"}
    # /admin/login must end up in the notable URLs.
    assert any("admin" in u["url"] for u in out["interesting_urls"])


def test_wayback_no_capture(monkeypatch):
    """CDX returning only the header (or nothing) → note, no error."""
    monkeypatch.setattr(wb_mod, "get_json", lambda *a, **k: [["original", "timestamp"]])

    out = wb_mod.wayback_lookup("example.com")

    assert out["capture_count"] == 0
    assert "note" in out


# --------------------------- tech_fingerprint ---------------------------

class _FakeResponse:
    def __init__(self, headers, url="https://example.com/", status=200):
        self.headers = headers
        self.url = url
        self.status_code = status

    def close(self):
        pass


def test_tech_fingerprint_detects_stack_and_headers(monkeypatch):
    """Infers the stack and counts present/missing security headers."""
    monkeypatch.setattr(
        fp_mod,
        "get_response",
        lambda *a, **k: _FakeResponse(
            {
                "Server": "nginx",
                "X-Powered-By": "PHP/8.2",
                "Strict-Transport-Security": "max-age=63072000",
                "X-Frame-Options": "DENY",
            }
        ),
    )

    out = fp_mod.tech_fingerprint("example.com")

    assert out["server"] == "nginx"
    assert "nginx" in out["detected_tech"]
    assert "PHP" in out["detected_tech"]
    assert "HSTS" in out["security_headers_present"]
    assert "CSP" in out["security_headers_missing"]
    # 2 of 6 expected headers present → weak posture.
    assert out["hardening_score"] == "2/6"
    assert out["hardening_posture"] == "weak"


def test_tech_fingerprint_unreachable(monkeypatch):
    import requests

    def boom(*a, **k):
        raise requests.ConnectionError("down")

    monkeypatch.setattr(fp_mod, "get_response", boom)

    out = fp_mod.tech_fingerprint("example.com")
    assert "error" in out


# --------------------------- virustotal_lookup ---------------------------

def test_virustotal_without_key(monkeypatch):
    """Without VT_API_KEY: tool cleanly disabled, no error and no request."""
    monkeypatch.delenv("VT_API_KEY", raising=False)

    out = vt_mod.virustotal_lookup("example.com")

    assert out["enabled"] is False
    assert "note" in out
    assert "error" not in out


def test_virustotal_reputation_and_passive_dns(monkeypatch):
    """With a key: reputation + passive DNS shaped."""
    monkeypatch.setenv("VT_API_KEY", "fake-key")

    def fake_get_json(url, host, **kwargs):
        if url.endswith("/resolutions"):
            return {
                "data": [
                    {"attributes": {"ip_address": "1.2.3.4", "date": 1700000000}},
                ]
            }
        return {
            "data": {
                "attributes": {
                    "reputation": -5,
                    "last_analysis_stats": {"harmless": 60, "malicious": 3, "suspicious": 1},
                    "total_votes": {"malicious": 2, "harmless": 10},
                    "categories": {"engineX": "malware"},
                }
            }
        }

    monkeypatch.setattr(vt_mod, "get_json", fake_get_json)

    out = vt_mod.virustotal_lookup("example.com")

    assert out["enabled"] is True
    assert out["found"] is True
    assert out["reputation"] == -5
    assert out["last_analysis_stats"]["malicious"] == 3
    assert out["categories"] == ["malware"]
    assert out["passive_dns"][0]["ip_address"] == "1.2.3.4"
    # Epoch converted in code (1700000000 = 2023-11-14T22:13:20Z), never left to the LLM.
    assert out["passive_dns"][0]["last_resolved"] == "2023-11-14"


def test_virustotal_normalize_converts_legacy_epochs_idempotently():
    """Results recorded before ISO dates (raw epochs) get the live format."""
    legacy = {
        "domain": "example.com",
        "passive_dns": [
            {"ip_address": "1.2.3.4", "last_resolved": 1456963200},
            {"ip_address": "5.6.7.8", "last_resolved": None},
        ],
    }

    once = vt_mod.normalize_result(legacy)

    assert once["passive_dns"][0]["last_resolved"] == "2016-03-03"
    assert once["passive_dns"][1]["last_resolved"] is None
    assert vt_mod.normalize_result(once) == once
    assert legacy["passive_dns"][0]["last_resolved"] == 1456963200  # input untouched


def test_virustotal_replayed_fixture_gets_iso_dates(monkeypatch):
    """--replay of a committed fixture (raw epochs on disk) yields ISO dates.

    pets.com is the measured case: the LLM wrote 2016-01-01 for this entry."""
    monkeypatch.setenv("OSINTLLM_FIXTURE_MODE", "replay")
    monkeypatch.setattr(
        fixtures, "FIXTURES_ROOT", Path(__file__).resolve().parents[1] / "evals" / "fixtures"
    )
    fixtures.set_current_domain("pets.com")

    out = vt_mod.virustotal_tool.run(domain="pets.com")

    dates = [e["last_resolved"] for e in out["passive_dns"]]
    assert dates == ["2022-11-24", "2019-12-02", "2016-03-03", "2014-06-30"]


def test_virustotal_quota_exceeded(monkeypatch):
    """A 429 on reputation → clear quota message, no exception."""
    monkeypatch.setenv("VT_API_KEY", "fake-key")

    import requests

    def raise_429(*a, **k):
        resp = requests.Response()
        resp.status_code = 429
        raise requests.HTTPError(response=resp)

    monkeypatch.setattr(vt_mod, "get_json", raise_429)

    out = vt_mod.virustotal_lookup("example.com")

    assert "error" in out
    assert "quota" in out["error"]
