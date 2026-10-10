"""`make eval-adversarial` entry point — runs the adversarial suite's cases
(see cases.py), writes evals/adversarial/results/<timestamp>.json and a
Markdown summary, prints a table per family.

Usage:
    python evals/run_adversarial.py                    # all cases, 1 repetition
    python evals/run_adversarial.py --cases direct_instruction_whois
    python evals/run_adversarial.py --repetitions 3     # for a more robust measurement
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any

from .cases import CASES
from .runner import run_case

RESULTS_DIR = Path(__file__).resolve().parent / "results"


def _row(case_name: str, family: str, rep_results: list[dict[str, Any]]) -> dict[str, Any]:
    measured = [r for r in rep_results if r["succeeded"] is not None]
    n_measured = len(measured)
    n_succeeded = sum(1 for r in measured if r["succeeded"])
    rate = (n_succeeded / n_measured) if n_measured else None
    return {
        "case": case_name,
        "family": family,
        "n_repetitions": len(rep_results),
        "n_measured": n_measured,
        "n_succeeded": n_succeeded,
        "success_rate": rate,
        "repetitions": rep_results,
    }


def render_markdown(rows: list[dict[str, Any]]) -> str:
    lines = [
        "| Family | Case | Measured / repetitions | Attack success |",
        "|---|---|---|---|",
    ]
    for row in rows:
        rate = "—" if row["success_rate"] is None else f"{row['success_rate'] * 100:.0f}%"
        lines.append(
            f"| {row['family']} | {row['case']} "
            f"| {row['n_measured']}/{row['n_repetitions']} | {rate} |"
        )

    by_family: dict[str, list[float]] = {}
    for row in rows:
        if row["success_rate"] is not None:
            by_family.setdefault(row["family"], []).append(row["success_rate"])
    if by_family:
        lines += ["", "### Mean success rate by family", ""]
        lines += ["| Family | Mean success rate |", "|---|---|"]
        for fam, rates in sorted(by_family.items()):
            lines.append(f"| {fam} | {sum(rates) / len(rates) * 100:.0f}% |")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="osintllm adversarial suite (Phase 4)")
    parser.add_argument(
        "--cases", nargs="*", default=None, help="Subset of cases by name (default: all)"
    )
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    cases = [c for c in CASES if args.cases is None or c.name in args.cases]
    if args.cases:
        missing = set(args.cases) - {c.name for c in cases}
        if missing:
            print(f"Unknown cases: {sorted(missing)}", file=sys.stderr)
            return 2

    print(
        f"Cases: {len(cases)} · repetitions: {args.repetitions}",
        file=sys.stderr,
    )

    rows: list[dict[str, Any]] = []
    for case in cases:
        rep_results = []
        for rep in range(1, args.repetitions + 1):
            outcome = run_case(case, seed=args.seed + rep)
            rep_results.append(
                {
                    "repetition": rep,
                    "succeeded": outcome.succeeded,
                    "detail": outcome.detail,
                    "error": outcome.error,
                    "injection_detected": outcome.injection_detected,
                }
            )
            if outcome.succeeded is None:
                status = "?"
            else:
                status = "ATTACK SUCCEEDED" if outcome.succeeded else "blocked"
            print(f"[{case.name} | rep{rep}] {status} — {outcome.detail}", file=sys.stderr)
        rows.append(_row(case.name, case.family, rep_results))

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = f"{dt.datetime.now(dt.timezone.utc):%Y%m%d_%H%M%S}"
    out_path = args.out or RESULTS_DIR / f"{stamp}.json"
    payload = {
        "meta": {
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "n_cases": len(cases),
            "n_repetitions": args.repetitions,
        },
        "rows": rows,
    }
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    md = render_markdown(rows)
    out_path.with_suffix(".md").write_text(md, encoding="utf-8")

    print(f"\nResults written to {out_path} and {out_path.with_suffix('.md')}", file=sys.stderr)
    print("\n" + md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
