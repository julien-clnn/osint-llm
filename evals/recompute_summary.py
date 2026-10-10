"""Recompute `summary` (evals/harness/cli.summarize) and the Markdown of a
result already written to disk, from its stored raw data (`runs`, `judge`,
`verifier_detection`) — WITHOUT re-running any LLM call.

Useful when the aggregation logic changes (e.g. adding the soft layer in
Phase 2) but the original run remains the reference: avoids paying for a
full run again just for a new way of counting what is already there.

Usage:
    python evals/recompute_summary.py evals/results/20260912_215745.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from osintllm.config import Settings  # noqa: E402

from evals.harness.aggregate import render_markdown_summary, to_jsonable  # noqa: E402
from evals.harness.cli import summarize  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 1:
        print("Usage: python evals/recompute_summary.py <result.json>", file=sys.stderr)
        return 1

    path = Path(argv[0])
    data = json.loads(path.read_text(encoding="utf-8"))
    meta = data["summary"]["meta"]
    settings = Settings(provider=meta["provider"], model=meta["model"])
    placeholder_domains = list(range(meta["n_domains"]))  # summarize() only uses len(domains)

    summary = summarize(
        data["runs"],
        data["verifier_detection"],
        placeholder_domains,
        meta["n_repetitions"],
        settings,
        data["judge"],
    )
    summary["meta"]["generated_at"] = meta["generated_at"]  # recomputation, not a new run

    data["summary"] = summary
    path.write_text(json.dumps(to_jsonable(data), ensure_ascii=False, indent=2), encoding="utf-8")

    md = render_markdown_summary(summary)
    path.with_suffix(".md").write_text(md, encoding="utf-8")

    print(f"Summary recomputed in {path} and {path.with_suffix('.md')}", file=sys.stderr)
    print("\n" + md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
