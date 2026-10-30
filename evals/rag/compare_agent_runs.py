"""Overhead of the ATT&CK layer: compare two agent-level eval result files,
one run with `--attack-rag off` (baseline) and one with `--attack-rag on`,
same code, same domains, same repetitions, same provider.

Prints (and writes next to the "on" file, as <stem>_vs_baseline.md) a table
per config: completion rate, tokens/run, latency/run, LLM calls/run, with
the absolute and relative delta. No API call.

Usage:
    python evals/rag/compare_agent_runs.py evals/results/<off>.json evals/results/<on>.json
"""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path


def _per_config(path: Path) -> tuple[dict, dict[str, dict[str, float]]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, dict[str, float]] = {}
    for cfg, block in data["summary"]["by_config"].items():
        runs = [r for r in data["runs"] if r["config"] == cfg and "error" not in r]
        if not runs:
            continue
        out[cfg] = {
            "runs": len(runs),
            "completion_rate": block["completion_rate"],
            "tokens_per_run": block["total_tokens_mean"],
            "seconds_per_run": block["wall_seconds_mean"],
            "llm_calls_per_run": statistics.mean(r["llm_call_count"] for r in runs),
        }
    return data["summary"]["meta"], out


def _delta(off: float, on: float) -> str:
    rel = f" ({(on - off) / off * 100:+.0f}%)" if off else ""
    return f"{on - off:+,.2f}{rel}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("baseline", type=Path, help="result file run with --attack-rag off")
    parser.add_argument("with_rag", type=Path, help="result file run with --attack-rag on")
    args = parser.parse_args(argv)

    meta_off, off = _per_config(args.baseline)
    meta_on, on = _per_config(args.with_rag)
    if meta_off.get("attack_rag") is not False or meta_on.get("attack_rag") is not True:
        raise SystemExit("expected a baseline run with the layer off and one with it on")
    for key in ("provider", "model", "scenario", "n_domains", "n_repetitions"):
        if meta_off.get(key) != meta_on.get(key):
            raise SystemExit(f"runs not comparable: {key} {meta_off.get(key)!r} "
                             f"vs {meta_on.get(key)!r}")

    lines = [
        f"# ATT&CK layer overhead — {meta_on['provider']}/{meta_on['model']}",
        "",
        f"Baseline `{args.baseline.name}` (layer off) vs `{args.with_rag.name}` (layer on), "
        f"{meta_on['n_domains']} domains x {meta_on['n_repetitions']} repetitions.",
        "",
        "| Config | Metric | Off | On | Delta |",
        "|---|---|---|---|---|",
    ]
    for cfg in sorted(set(off) & set(on)):
        for metric in ("completion_rate", "tokens_per_run", "seconds_per_run",
                       "llm_calls_per_run"):
            a, b = off[cfg][metric], on[cfg][metric]
            lines.append(f"| {cfg} | {metric} | {a:,.2f} | {b:,.2f} | {_delta(a, b)} |")
    markdown = "\n".join(lines) + "\n"
    out = args.with_rag.with_name(f"{args.with_rag.stem}_vs_baseline.md")
    out.write_text(markdown, encoding="utf-8")
    print(markdown)
    print(f"Written {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
