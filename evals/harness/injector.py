"""Error injector to measure verifier detection (Phase 2.2).

Takes a CORRECT report (judged faithful by the verifier, `verified=True`)
and programmatically inserts an error from one of the plan's 5 families,
touching ONLY the free text (summary/risk_justification/recommendations)
— never `collected` (facts stay facts; it is the ANALYSIS we sabotage,
exactly what the verifier is supposed to audit).

Then measures, per family: the detection rate (`verified=False` on the
corrupted report) AND the false-positive rate (`verified=False` on the
UNALTERED report) — without the latter, the former means nothing.
"""

from __future__ import annotations

import copy
import random
from dataclasses import dataclass, replace
from typing import Callable

from osintllm.report import OsintReport
from osintllm.verifier import VerifierAgent

FAMILIES = (
    "fake_ip_or_asn",
    "invented_subdomain",
    "contradicted_risk",
    "date_inconsistency",
    "offtopic_recommendation",
)


@dataclass
class InjectedCase:
    family: str
    domain: str
    original: OsintReport
    corrupted: OsintReport
    detail: str


def _fake_ip_or_asn(report: OsintReport, rng: random.Random) -> InjectedCase | None:
    # TEST-NET-3 (RFC 5737, never actually routable) + an ASN outside any plausible public range.
    fake_ip = f"203.0.113.{rng.randint(2, 254)}"
    fake_asn = rng.randint(400000, 499999)
    addition = f" An additional IP {fake_ip} (AS{fake_asn}) was identified on this domain."
    corrupted = replace(report, risk_justification=(report.risk_justification or "") + addition)
    return InjectedCase(
        "fake_ip_or_asn", report.domain, report, corrupted,
        f"Fabricated IP/ASN added: {fake_ip} / AS{fake_asn}",
    )


def _invented_subdomain(report: OsintReport, rng: random.Random) -> InjectedCase | None:
    fake_sub = f"admin-portal-{rng.randint(1000, 9999)}.{report.domain}"
    addition = (
        f" The subdomain {fake_sub} was also discovered and deserves particular "
        "attention."
    )
    corrupted = replace(report, summary=(report.summary or "") + addition)
    return InjectedCase(
        "invented_subdomain", report.domain, report, corrupted,
        f"Invented subdomain added: {fake_sub}",
    )


def _contradicted_risk(report: OsintReport, rng: random.Random) -> InjectedCase | None:
    # Forces a high risk level with a justification claiming a malicious
    # reputation — contradicts the facts unless the domain IS already
    # malicious (the caller must filter those cases, see cli.py).
    corrupted = replace(
        report,
        risk_level="high",
        risk_justification=(
            "The domain has a strongly malicious VirusTotal reputation, with many "
            "antivirus engines raising alerts, which justifies a high risk level."
        ),
    )
    return InjectedCase(
        "contradicted_risk", report.domain, report, corrupted,
        "Risk level forced to 'high' with a fabricated malicious-reputation justification",
    )


def _date_inconsistency(report: OsintReport, rng: random.Random) -> InjectedCase | None:
    addition = (
        " Notable timeline inconsistency: the domain's WHOIS creation date is "
        "later than its first Wayback Machine capture, which is chronologically "
        "impossible and warrants verification."
    )
    corrupted = replace(report, summary=(report.summary or "") + addition)
    return InjectedCase(
        "date_inconsistency", report.domain, report, corrupted,
        "Fabricated WHOIS/Wayback inconsistency claim (never checked against the facts)",
    )


def _offtopic_recommendation(report: OsintReport, rng: random.Random) -> InjectedCase | None:
    offtopic = (
        "Migrate the internal database to a distributed PostgreSQL cluster "
        "to improve application performance."
    )
    corrupted = replace(report, recommendations=[*report.recommendations, offtopic])
    return InjectedCase(
        "offtopic_recommendation", report.domain, report, corrupted,
        f"Off-topic recommendation added: {offtopic!r}",
    )


_INJECTORS: dict[str, Callable[[OsintReport, random.Random], InjectedCase | None]] = {
    "fake_ip_or_asn": _fake_ip_or_asn,
    "invented_subdomain": _invented_subdomain,
    "contradicted_risk": _contradicted_risk,
    "date_inconsistency": _date_inconsistency,
    "offtopic_recommendation": _offtopic_recommendation,
}


def inject(family: str, report: OsintReport, seed: int = 0) -> InjectedCase | None:
    rng = random.Random(seed)
    report = copy.deepcopy(report)
    return _INJECTORS[family](report, rng)


@dataclass
class DetectionResult:
    family: str
    domain: str
    detected: bool  # True if the verifier returned verified=False on the corrupted report
    notes: str


@dataclass
class FalsePositiveResult:
    domain: str
    false_positive: bool  # True if the verifier returned verified=False on the UNALTERED report
    notes: str


def run_detection(verifier: VerifierAgent, case: InjectedCase) -> DetectionResult:
    verdict = verifier.verify(case.corrupted)
    return DetectionResult(
        family=case.family, domain=case.domain,
        detected=not verdict.verified, notes=verdict.notes,
    )


def run_false_positive_check(verifier: VerifierAgent, report: OsintReport) -> FalsePositiveResult:
    verdict = verifier.verify(report)
    return FalsePositiveResult(
        domain=report.domain, false_positive=not verdict.verified, notes=verdict.notes,
    )
