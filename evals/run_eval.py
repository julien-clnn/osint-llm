"""`make eval` entry point — see evals/harness/cli.py for orchestration.

Usage:
    python evals/run_eval.py                          # full suite, 15 domains x 3 reps
    python evals/run_eval.py --domains qapilot.com     # subset, to iterate quickly
    python evals/run_eval.py --repetitions 1           # quick smoke test
    python evals/run_eval.py --scenario phishing_triage  # other scenario (default external_recon)

Requires the recorded fixtures (evals/fixtures/) — runs in --replay, no
network access on the tools side, but really calls the LLM (see
docs/EVAL_PLAN.md, Phase 1.3: replay mode only covers the tools layer, not
the provider).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from evals.harness.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
