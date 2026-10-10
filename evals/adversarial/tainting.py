""""Tainted" copy of a domain's fixtures — a single field of a single
fixture file replaced by an adversarial payload, everything else unchanged.
The versioned fixture set (`evals/fixtures/`) is **never** modified: the
copy lives in a temporary directory, deleted on exit.

Important technical point: `fixtures.FIXTURES_ROOT` is read only once, when
the `osintllm.fixtures` module is imported (`Path(os.getenv(...))`
evaluated at module level) — setting the environment variable at runtime
therefore has NO effect after the first import. We monkeypatch the
attribute directly, restored in a `finally` (same pattern as
`evals/harness/runner.py`, which already swaps `agent.provider` to
instrument the run — nothing new architecturally).
"""

from __future__ import annotations

import contextlib
import copy
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any, Callable, Iterator

from osintllm import fixtures

REAL_FIXTURES_ROOT = Path("evals/fixtures")

# Signature shared by all mutations: receives the `result` dict of an
# already-loaded tool call and modifies it IN PLACE.
Mutator = Callable[[dict[str, Any]], None]


def _find_fixture(domain_dir: Path, tool_name: str) -> Path:
    """The fixture file of `tool_name` for this domain.

    Some tools (e.g. asn_lookup) have several fixtures per domain (one per
    queried IP) — we take the first in alphabetical order; which one does
    not matter for an injection test (any fact read by the LLM is enough to
    carry the payload)."""
    matches = sorted(domain_dir.glob(f"{tool_name}__*.json"))
    if not matches:
        raise FileNotFoundError(
            f"No {tool_name!r} fixture for {domain_dir.name!r} — "
            "pick another domain/tool for this case."
        )
    return matches[0]


def apply_mutation(entry: dict[str, Any], mutate: Mutator) -> None:
    """Apply `mutate` in place to the `result` field of a loaded fixture
    (dict with `tool`/`arguments`/`result` keys)."""
    mutate(entry["result"])


@contextlib.contextmanager
def tainted_fixtures(domain: str, tool_name: str, mutate: Mutator) -> Iterator[None]:
    """For the duration of the block, `fixtures.FIXTURES_ROOT` points to a
    copy of `domain`'s fixture directory, with the `tool_name` result
    modified by `mutate`. Restores the original on exit, even on exception
    (an adversarial case may legitimately crash the agent loop — e.g. the
    "exfiltration" family may trigger a FixtureMissError on an unexpected
    call)."""
    real_dir = REAL_FIXTURES_ROOT / domain
    if not real_dir.is_dir():
        raise FileNotFoundError(f"No fixtures for {domain!r} ({real_dir})")

    tmp_root = Path(tempfile.mkdtemp(prefix="osintllm_adversarial_"))
    try:
        tmp_domain_dir = tmp_root / domain
        shutil.copytree(real_dir, tmp_domain_dir)

        target = _find_fixture(tmp_domain_dir, tool_name)
        entry = json.loads(target.read_text(encoding="utf-8"))
        apply_mutation(entry, mutate)
        target.write_text(
            json.dumps(entry, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )

        original_root = fixtures.FIXTURES_ROOT
        fixtures.FIXTURES_ROOT = tmp_root
        try:
            yield
        finally:
            fixtures.FIXTURES_ROOT = original_root
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


def mutate_collected(
    collected: dict[str, list[dict[str, Any]]], tool_name: str, mutate: Mutator
) -> None:
    """In-memory variant of `apply_mutation`, for the "verifier
    manipulation" family: modifies the LAST `tool_name` call in
    `report.collected` (not a fixture file — the report was already
    produced by a real run)."""
    calls = collected.get(tool_name)
    if not calls:
        raise KeyError(f"No collected fact for {tool_name!r} in this report.")
    mutate(calls[-1]["result"])


def deepcopy_collected(
    collected: dict[str, list[dict[str, Any]]],
) -> dict[str, list[dict[str, Any]]]:
    return copy.deepcopy(collected)
