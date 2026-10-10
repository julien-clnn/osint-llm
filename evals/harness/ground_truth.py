"""Ground truth loading (evals/ground_truth/<domain>.yaml).

Schema documented in evals/ground_truth/README.md. This module only loads
and normalizes — no metrics here.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

GROUND_TRUTH_DIR = Path(__file__).resolve().parent.parent / "ground_truth"


@dataclass
class GroundTruth:
    domain: str
    subdomains_expected_count: int | None
    subdomains_known_sample: list[str]
    subdomains_known_exclusions: list[str]
    spf: bool | None
    dmarc: bool | None
    dmarc_policy: str | None
    dkim_selectors_found: list[str]
    expected_asn: int | None
    expected_org_substring: str | None
    behind_cdn_proxy: bool
    reputation_verdict: str
    malicious_engines_min: int
    must_contain: list[str]
    must_not_contain: list[str]
    notes: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GroundTruth":
        sub = data.get("subdomains", {}) or {}
        sec = data.get("email_security", {}) or {}
        net = data.get("network", {}) or {}
        rep = data.get("reputation", {}) or {}
        return cls(
            domain=data["domain"],
            subdomains_expected_count=sub.get("expected_count"),
            subdomains_known_sample=sub.get("known_sample", []) or [],
            subdomains_known_exclusions=sub.get("known_exclusions", []) or [],
            spf=sec.get("spf"),
            dmarc=sec.get("dmarc"),
            dmarc_policy=sec.get("dmarc_policy"),
            dkim_selectors_found=sec.get("dkim_selectors_found", []) or [],
            expected_asn=net.get("expected_asn"),
            expected_org_substring=net.get("expected_org_substring"),
            behind_cdn_proxy=bool(net.get("behind_cdn_proxy", False)),
            reputation_verdict=rep.get("verdict", "unknown"),
            malicious_engines_min=rep.get("malicious_engines_min", 0) or 0,
            must_contain=data.get("must_contain", []) or [],
            must_not_contain=data.get("must_not_contain", []) or [],
            notes=data.get("notes", "") or "",
        )


def load_ground_truth(domain: str) -> GroundTruth:
    path = GROUND_TRUTH_DIR / f"{domain}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"No ground truth for {domain!r} ({path})")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return GroundTruth.from_dict(data)


def list_domains() -> list[str]:
    return sorted(p.stem for p in GROUND_TRUTH_DIR.glob("*.yaml"))
