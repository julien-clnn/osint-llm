"""Eval harness: ATT&CK aggregates and rendering, on fake run rows (no LLM).

Guards the two traps of the agent-level eval: ATT&CK counters must be
aggregated per config, and a skipped detection pass (--no-detection) must
not render as a 0% detection rate.
"""

from __future__ import annotations

import os

os.environ.setdefault("DEEPSEEK_API_KEY", "fake-key-for-tests")

from evals.harness.aggregate import render_markdown_summary  # noqa: E402
from evals.harness.cli import summarize  # noqa: E402
from osintllm.config import Settings  # noqa: E402


def _row(config: str, mappings: int, invented: int, stripped: int, final: int) -> dict:
    return {
        "domain": "example.com", "config": config, "repetition": 1, "completed": True,
        "hallucination_hard": 0.0, "recall": 1.0, "precision": 1.0, "tool_calls": 9,
        "redundant_calls": 0, "missed_calls": [], "total_tokens": 1000, "wall_seconds": 2.0,
        "correction_rounds": 1 if config == "with_verifier" else None,
        "attack_lookup_calls": 1, "attack_mappings": mappings,
        "invented_ids_initial": invented, "invented_ids_stripped": stripped,
        "invented_ids_final": final,
    }


def test_attack_aggregates_and_skipped_detection():
    rows = [
        _row("without_verifier", 2, 1, 0, 1),
        _row("without_verifier", 0, 0, 0, 0),
        _row("with_verifier", 2, 1, 0, 0),
        _row("with_verifier", 1, 0, 0, 0),
    ]
    summary = summarize(
        rows, {"detections": [], "false_positives": []}, ["example.com"], 2,
        Settings(api_key="x", attack_rag=True),
    )
    attack = summary["by_config"]["without_verifier"]["attack"]
    assert attack["share_runs_with_mapping"] == 0.5
    assert attack["invented_ids_initial_total"] == 1
    assert attack["invented_ids_final_total"] == 1
    assert summary["by_config"]["with_verifier"]["attack"]["invented_ids_final_total"] == 0
    assert summary["verifier_detection"] is None
    assert summary["meta"]["attack_rag"] is True

    md = render_markdown_summary(summary)
    assert "ATT&CK layer on" in md
    assert "### MITRE ATT&CK layer" in md
    assert "Verifier detection" not in md


def test_results_without_attack_counters_render_no_attack_section():
    row = _row("with_verifier", 0, 0, 0, 0)
    for key in ("attack_lookup_calls", "attack_mappings", "invented_ids_initial",
                "invented_ids_stripped", "invented_ids_final"):
        row.pop(key)
    summary = summarize([row], {"detections": [], "false_positives": []}, ["example.com"], 1,
                        Settings(api_key="x"))
    assert summary["by_config"]["with_verifier"]["attack"] is None
    assert "MITRE ATT&CK" not in render_markdown_summary(summary)


def test_summary_skips_configs_that_were_not_run():
    summary = summarize([_row("with_verifier", 1, 0, 0, 0)],
                        {"detections": [], "false_positives": []}, ["example.com"], 1,
                        Settings(api_key="x", attack_rag=True))
    assert list(summary["by_config"]) == ["with_verifier"]
    assert "without_verifier" not in render_markdown_summary(summary)
