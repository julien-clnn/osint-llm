"""Aggregation (mean + standard deviation over repetitions) and Markdown
rendering of the results (Phase 2.3). No metric is computed here — only
descriptive statistics over what `cli.py` already produced.
"""

from __future__ import annotations

import statistics as stats
from dataclasses import asdict, is_dataclass
from typing import Any


def mean_std(values: list[float]) -> tuple[float | None, float | None]:
    """Mean + (sample) standard deviation. None if there is no usable value."""
    clean = [v for v in values if v is not None]
    if not clean:
        return None, None
    mean = stats.mean(clean)
    std = stats.stdev(clean) if len(clean) > 1 else 0.0
    return mean, std


def to_jsonable(obj: Any) -> Any:
    """Recursively convert dataclasses/objects into JSON-safe structures."""
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: to_jsonable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [to_jsonable(v) for v in obj]
    return obj


def fmt(mean: float | None, std: float | None, digits: int = 2) -> str:
    if mean is None:
        return "—"
    if std is None:
        return f"{mean:.{digits}f}"
    return f"{mean:.{digits}f} ± {std:.{digits}f}"


def render_markdown_summary(summary: dict[str, Any]) -> str:
    """Render the Markdown summary table injected into the README."""
    meta = summary["meta"]
    scenario_name = meta.get("scenario", "external_recon")
    scenario_suffix = f" · scenario {scenario_name}" if scenario_name != "external_recon" else ""
    lines = [
        f"_Generated on {meta['generated_at']} · provider {meta['provider']}/{meta['model']} · "
        f"{meta['n_domains']} domains · {meta['n_repetitions']} repetitions per configuration"
        f"{scenario_suffix}"
        + (f" · ATT&CK layer {'on' if meta['attack_rag'] else 'off'}" if "attack_rag" in meta
           else "")
        + "._",
        "",
        "| Config | Runs (ok/attempted) | Completion | Hard halluc. | Subdomains (R/P) "
        "| Tool calls (total/redundant/missed) | Tokens/run | Latency/run (s) "
        "| Revisions/run |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for cfg_name, cfg in summary["by_config"].items():
        recall_fmt = fmt(cfg["recall_mean"], cfg["recall_std"])
        precision_fmt = fmt(cfg["precision_mean"], cfg["precision_std"])
        recall_p = f"{recall_fmt} / {precision_fmt}"
        calls = (
            f"{fmt(cfg['tool_calls_mean'], None, 1)} / "
            f"{fmt(cfg['redundant_calls_mean'], None, 1)} / "
            f"{cfg['missed_calls_avg_count']:.1f}"
        )
        runs_col = f"{cfg['n_runs_ok']}/{cfg['n_runs_attempted']}"
        if cfg["n_runs_errored"]:
            runs_col += f" ({cfg['run_error_rate'] * 100:.0f}% errored)"
        corrections_col = fmt(cfg["correction_rounds_mean"], cfg["correction_rounds_std"], 2)
        lines.append(
            f"| {cfg_name} "
            f"| {runs_col} "
            f"| {cfg['completion_rate'] * 100:.0f}% "
            f"| {fmt(cfg['hallucination_hard_mean'], cfg['hallucination_hard_std'], 3)} "
            f"| {recall_p} "
            f"| {calls} "
            f"| {fmt(cfg['total_tokens_mean'], cfg['total_tokens_std'], 0)} "
            f"| {fmt(cfg['wall_seconds_mean'], cfg['wall_seconds_std'], 1)} "
            f"| {corrections_col} |"
        )

    attack_rows = [(n, c["attack"]) for n, c in summary["by_config"].items() if c.get("attack")]
    if attack_rows:
        lines += ["", "### MITRE ATT&CK layer", ""]
        lines += [
            "| Config | Runs with ≥1 mapping | Runs calling attack_lookup | Mappings/run "
            "| Invented IDs: initial report (runs) | Removed by final guard | In final report |",
            "|---|---|---|---|---|---|---|",
        ]
        for cfg_name, a in attack_rows:
            lines.append(
                f"| {cfg_name} | {a['share_runs_with_mapping'] * 100:.0f}% "
                f"| {a['share_runs_calling_lookup'] * 100:.0f}% "
                f"| {a['mappings_mean']:.2f} "
                f"| {a['invented_ids_initial_total']} ({a['runs_with_invented_initial']}) "
                f"| {a['invented_ids_stripped_total']} | {a['invented_ids_final_total']} |"
            )

    detection = summary.get("verifier_detection")
    if detection:
        lines += ["", "### Verifier detection, by injected error family", ""]
        lines += [
            "| Family | Detection rate | False-positive rate (intact report) |",
            "|---|---|---|",
        ]
        fp_rate = detection["false_positive_rate"]
        for fam, rate in detection["by_family"].items():
            lines.append(
                f"| {fam} | {rate * 100:.0f}% | {fp_rate * 100:.0f}% "
                "(shared across all families) |"
            )

    soft = summary.get("judge_soft")
    if soft:
        lines += ["", "### Soft layer (LLM judge), on reports with verifier", ""]
        lines += ["| Metric | Value |", "|---|---|"]
        lines.append(
            f"| Soft hallucination (unsupported/contradicted claims) "
            f"| {_pct_or_dash(soft['hallucination_soft'])} |"
        )
        lines.append(
            f"| Ground truth assertions respected "
            f"| {_pct_or_dash(soft['assertions_respected_rate'])} |"
        )
        lines.append(
            f"| Domains with judging failure (global judge_error) "
            f"| {soft['n_domain_errors']}/{soft['n_domains']} "
            f"({_pct_or_dash(soft['domain_error_rate'])}) |"
        )
        lines.append(
            f"| Unjudged claims (judge_error) "
            f"| {_pct_or_dash(soft['claim_judge_error_rate'])} of {soft['n_claims_judged']} |"
        )
        lines.append(
            f"| Unjudged assertions (judge_error) "
            f"| {_pct_or_dash(soft['assertion_judge_error_rate'])} "
            f"of {soft['n_assertions_judged']} |"
        )

    phishing = summary.get("phishing_verdict")
    if phishing:
        lines += ["", "### Verdict accuracy (phishing_triage scenario)", ""]
        lines += ["| Metric | Value |", "|---|---|"]
        lines.append(f"| Judgeable verdicts (known malicious/benign) | {phishing['n_judged']} |")
        lines.append(f"| Accuracy | {_pct_or_dash(phishing['accuracy'])} |")

    return "\n".join(lines)


def _pct_or_dash(value: float | None) -> str:
    return f"{value * 100:.1f}%" if value is not None else "—"
