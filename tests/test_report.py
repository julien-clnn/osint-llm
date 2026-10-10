"""OSINT report tests: data extraction and exports."""

from __future__ import annotations

import json

from osintllm.report import OsintReport


def _sample_report() -> OsintReport:
    return OsintReport(
        domain="example.com",
        summary="IANA reserved domain.",
        risk_level="low",
        risk_justification="No abnormal exposure.",
        recommendations=["Enable DNSSEC", "Monitor expiration"],
        collected={
            "ip_geolocate": [
                {
                    "arguments": {"target": "example.com"},
                    "result": {
                        "locations": [
                            {"ip": "1.2.3.4", "city": "Toronto", "country": "Canada",
                             "org": "Cloudflare", "as": "AS13335", "lat": 43.6, "lon": -79.3},
                            {"ip": "5.6.7.8", "city": None, "country": None,
                             "org": None, "as": None},  # no coordinates
                        ]
                    },
                }
            ],
            "enumerate_subdomains": [
                {
                    "arguments": {"domain": "example.com"},
                    "result": {"subdomains": ["a.example.com", "b.example.com", "a.example.com"]},
                }
            ],
        },
        iterations=3,
        stopped_reason="report_submitted",
    )


def test_locations_returns_all_ips():
    rep = _sample_report()
    locs = rep.locations()
    assert len(locs) == 2
    assert locs[0]["ip"] == "1.2.3.4"


def test_subdomains_deduplicated_and_sorted():
    rep = _sample_report()
    assert rep.subdomains() == ["a.example.com", "b.example.com"]


def test_to_json_is_valid():
    rep = _sample_report()
    data = json.loads(rep.to_json())
    assert data["domain"] == "example.com"
    assert data["risk_level"] == "low"


def test_to_html_contains_sections():
    rep = _sample_report()
    doc = rep.to_html()
    assert doc.startswith("<!doctype html>")
    assert "OSINT report — example.com" in doc
    assert "LOW" in doc
    assert "Enable DNSSEC" in doc
    assert "a.example.com" in doc
    assert "1.2.3.4" in doc


def test_to_html_escapes_content():
    """Booby-trapped content must not break the HTML (anti-injection)."""
    rep = OsintReport(domain="x.com", summary="<script>alert(1)</script>")
    doc = rep.to_html()
    assert "<script>alert(1)</script>" not in doc
    assert "&lt;script&gt;" in doc


def test_to_markdown_contains_risk():
    rep = _sample_report()
    md = rep.to_markdown()
    assert "# OSINT report — example.com" in md
    assert "LOW" in md


def test_legacy_french_risk_level_is_rendered():
    """Archived French reports still render with the matching risk badge."""
    rep = OsintReport(domain="x.com", risk_level="élevé")
    assert "HIGH" in rep.to_html()
