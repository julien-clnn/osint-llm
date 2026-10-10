"""Completion, subdomain recall/precision, and orchestration efficiency
metrics (Phase 2.2) — all computed from a `RunRecord` and the ground truth
of the matching domain.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .ground_truth import GroundTruth
from .runner import RunRecord

# Legacy French values are kept so archived runs (evals/results/) can still
# be recomputed.
COMPLETED_REASONS = {"report_submitted", "report_revised", "rapport_soumis", "rapport_corrige"}

_LEGACY_RISK_LEVELS = {
    "faible": "low",
    "moyen": "medium",
    "élevé": "high",
    "indéterminé": "undetermined",
}


def normalize_risk_level(value: str | None) -> str | None:
    """Map legacy French `risk_level` values to their English equivalent."""
    if value is None:
        return None
    return _LEGACY_RISK_LEVELS.get(value, value)


def completed_cleanly(record: RunRecord) -> bool:
    """True if the run ended via submit_report, with or without revision —
    False if it looped (max_iterations) or went off track (free_text)."""
    return record.report.stopped_reason in COMPLETED_REASONS


@dataclass
class SubdomainScore:
    recall: float | None       # share of known_sample found in the report
    precision: float | None    # share of reported subdomains that are known expected/excluded


def subdomain_recall_precision(record: RunRecord, gt: GroundTruth) -> SubdomainScore:
    expected = {s.lower() for s in gt.subdomains_known_sample}
    excluded_ok = {s.lower() for s in gt.subdomains_known_exclusions}
    found = {s.lower() for s in record.report.subdomains()}

    if not expected:
        recall = None
    else:
        recall = len(expected & found) / len(expected)

    if not found:
        precision = None
    else:
        # a found subdomain is "correct" if it belongs to the known sample OR
        # the known exclusions (expected noise) — the rest is neither confirmed
        # nor refuted by a ground truth that is deliberately partial on domains
        # with a very large surface (see evals/ground_truth/README.md).
        plausible = expected | excluded_ok
        precision = len(found & plausible) / len(found) if plausible else None

    return SubdomainScore(recall=recall, precision=precision)


# Tool required to check a given non-null ground truth field.
_REQUIRED_TOOL_FOR_FIELD = [
    ("whois_lookup", lambda gt: True),  # always expected
    ("enumerate_subdomains", lambda gt: gt.subdomains_expected_count is not None),
    ("dns_records_lookup", lambda gt: gt.spf is not None or gt.dmarc is not None),
    ("asn_lookup", lambda gt: gt.expected_asn is not None),
    ("virustotal_lookup", lambda gt: gt.reputation_verdict != "unknown"),
]


@dataclass
class OrchestrationEfficiency:
    total_calls: int
    redundant_calls: int
    missed_calls: list[str]


def orchestration_efficiency(
    record: RunRecord, gt: GroundTruth, allowed_tools: set[str] | None = None
) -> OrchestrationEfficiency:
    """`allowed_tools` restricts "missed" calls to the tools the evaluated
    scenario actually exposes to the LLM (None = no restriction, historical
    behavior for `external_recon`) — otherwise a scenario that is never
    allowed to call `asn_lookup` (e.g. `phishing_triage`) would wrongly be
    counted as having "missed" it."""
    collected = record.report.collected
    total = sum(len(calls) for calls in collected.values())

    redundant = 0
    for tool_name, calls in collected.items():
        seen: set[str] = set()
        for call in calls:
            key = json.dumps(call.get("arguments", {}), sort_keys=True)
            if key in seen:
                redundant += 1
            seen.add(key)

    missed = [
        tool_name
        for tool_name, needed in _REQUIRED_TOOL_FOR_FIELD
        if needed(gt)
        and tool_name not in collected
        and (allowed_tools is None or tool_name in allowed_tools)
    ]

    return OrchestrationEfficiency(
        total_calls=total, redundant_calls=redundant, missed_calls=missed
    )


# Maps phishing_triage verdicts (see scenarios/phishing_triage.yaml:
# risk_level_mapping) to the ground truth verdicts
# (evals/ground_truth/*.yaml:reputation.verdict) this dataset actually
# covers so far (no "suspicious" domain yet). Legacy French verdicts are
# accepted alongside the English ones.
_VERDICT_TO_REPUTATION = {
    "malicious": "malicious",
    "benign": "clean",
    "malveillant": "malicious",
    "bénin": "clean",
}


def phishing_verdict_correct(record: RunRecord, gt: GroundTruth) -> bool | None:
    """True/False if the `phishing_triage` verdict (via `risk_level_mapping`)
    matches `gt.reputation_verdict`; None if either verdict is not
    comparable (e.g. "suspicious", "undetermined"/"unknown" — not covered by
    the current dataset, see evals/DATASET.md)."""
    from osintllm.scenarios import load_scenario  # late import: avoids an import cycle

    scenario = load_scenario("phishing_triage")
    mapping = {
        normalize_risk_level(level): verdict
        for level, verdict in (scenario.risk_level_mapping or {}).items()
    }
    verdict = mapping.get(normalize_risk_level(record.report.risk_level))
    if verdict is None:
        return None
    expected = _VERDICT_TO_REPUTATION.get(verdict)
    if expected is None or gt.reputation_verdict not in ("malicious", "clean"):
        return None
    return expected == gt.reputation_verdict
