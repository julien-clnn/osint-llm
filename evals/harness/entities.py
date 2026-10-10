"""HARD hallucination-detection layer (Phase 2.2).

Extracts the factual entities cited in the report's free text (summary,
risk_justification, recommendations) and checks that each one appears
LITERALLY in at least one tool observation of the run (`report.collected`,
serialized as JSON) — the only source of truth.

Covers: IPv4 addresses, AS/ASN numbers, ISO dates (YYYY-MM-DD), and
subdomains of the analyzed domain.

Known limitation: does not cover registrar names rephrased in free text, nor
dates rephrased in natural language ("August 18, 2026") — too ambiguous for
reliable regex extraction. Compensated by the soft layer (LLM judge, see
judge.py), which reasons about meaning rather than literal form.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from osintllm.report import OsintReport

_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_ASN_RE = re.compile(r"\bAS\s?N?\s?(\d{3,6})\b", re.IGNORECASE)
_ISO_DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")


@dataclass
class EntityCheck:
    entity_type: str  # "ip" | "asn" | "date" | "subdomain"
    value: str
    supported: bool


def _subdomain_regex(domain: str) -> re.Pattern[str]:
    escaped = re.escape(domain)
    return re.compile(rf"\b(?:[a-z0-9-]+\.)+{escaped}\b", re.IGNORECASE)


def _report_text(report: OsintReport) -> str:
    return " ".join(
        [report.summary or "", report.risk_justification or "", *report.recommendations]
    )


def extract_and_check(report: OsintReport) -> list[EntityCheck]:
    """Extract entities from the report's free text and check their literal
    support in `report.collected` (the raw facts collected by the tools)."""
    text = _report_text(report)
    haystack = json.dumps(report.collected, ensure_ascii=False)
    haystack_lower = haystack.lower()

    checks: list[EntityCheck] = []

    for m in set(_IPV4_RE.findall(text)):
        checks.append(EntityCheck("ip", m, m in haystack))

    for m in set(_ASN_RE.findall(text)):
        # look for the bare number (the ASN in collected is a JSON int, e.g. "asn": 8075)
        checks.append(EntityCheck("asn", m, re.search(rf'"asn":\s*{m}\b', haystack) is not None))

    for m in set(_ISO_DATE_RE.findall(text)):
        checks.append(EntityCheck("date", m, m in haystack))

    sub_re = _subdomain_regex(report.domain)
    for m in set(s.lower() for s in sub_re.findall(text)):
        checks.append(EntityCheck("subdomain", m, m in haystack_lower))

    return checks


def hallucination_rate_hard(report: OsintReport) -> float | None:
    """Share of UNSUPPORTED entities among those extracted. None if no entity
    was extracted (the report cites no verifiable factual entity)."""
    checks = extract_and_check(report)
    if not checks:
        return None
    unsupported = sum(1 for c in checks if not c.supported)
    return unsupported / len(checks)
