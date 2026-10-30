"""Labeling protocol of the ATT&CK retrieval eval set (see evals/rag/README.md).

Two independent labelers receive the SAME guideline and the same candidate
list (every live technique of the index: ID, name, tactics — never the
retrieval results, which would make the evaluation circular):
  - `deepseek-v4-pro` (label_with_deepseek.py);
  - an independent Claude agent, given `GUIDELINE` verbatim.
`build_gold.py` then keeps, per observation, the IDs both labelers agree on.
"""

from __future__ import annotations

import json
from pathlib import Path

RAG_DIR = Path(__file__).resolve().parent
OBSERVATIONS = RAG_DIR / "observations.json"
LABELS_DIR = RAG_DIR / "labels"
GOLD = RAG_DIR / "gold.json"

GUIDELINE = """\
You label findings from PASSIVE OSINT reconnaissance of an internet domain \
(WHOIS, DNS/SPF/DMARC, certificate-transparency subdomains, hosting/ASN, \
Wayback Machine history, HTTP headers, GitHub search, VirusTotal reputation) \
with MITRE ATT&CK Enterprise techniques.

For each observation, give the 1 to 3 ATT&CK techniques it most directly \
relates to, most relevant first: either the technique the observation is \
direct evidence of (e.g. infrastructure an adversary acquired), or the \
technique this weakness most directly enables an adversary to perform \
against the domain owner. Prefer a sub-technique when one fits precisely; \
otherwise use the parent technique. Only use IDs from the candidate list. \
If no technique is a reasonable match, return an empty list.
"""


def load_observations() -> list[dict]:
    return json.loads(OBSERVATIONS.read_text(encoding="utf-8"))["observations"]


def canonical_text(observation: dict) -> str:
    """The phrasing shown to labelers: the full-sentence analyst one."""
    return observation["phrasings"]["analyst"]


def candidate_list(index_dir: Path | None = None) -> str:
    """One line per live technique: `ID | name | tactics`."""
    path = (index_dir or RAG_DIR.parent.parent / "data" / "attack") / "techniques.json"
    techniques = json.loads(path.read_text(encoding="utf-8"))
    return "\n".join(
        f"{t['attack_id']} | {t['name']} | {', '.join(t['tactics'])}" for t in techniques
    )
