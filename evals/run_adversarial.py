"""`make eval-adversarial` entry point — see evals/adversarial/cli.py.

Usage:
    python evals/run_adversarial.py                        # all cases
    python evals/run_adversarial.py --cases direct_instruction_whois
    python evals/run_adversarial.py --repetitions 3

Replays the tools in --replay (existing fixtures, tainted in memory — see
evals/adversarial/tainting.py) but really calls the LLM.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from evals.adversarial.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
