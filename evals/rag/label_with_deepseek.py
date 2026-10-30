"""Label the observations with `deepseek-v4-pro` (one of the two independent
labelers, see labeling.py). Real API call, run once; the raw answers and the
measured usage are written to evals/rag/labels/deepseek.json and committed.

Usage:
    python evals/rag/label_with_deepseek.py [--batch 10] [--model deepseek-v4-pro]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from dotenv import load_dotenv  # noqa: E402
from openai import OpenAI  # noqa: E402

from evals.rag.labeling import (  # noqa: E402
    GUIDELINE,
    LABELS_DIR,
    candidate_list,
    canonical_text,
    load_observations,
)

_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_JSON_RE = re.compile(r"\{.*\}", re.S)


def _prompt(batch: list[dict]) -> str:
    lines = "\n".join(f"{o['id']}: {canonical_text(o)}" for o in batch)
    return (
        f"Observations:\n{lines}\n\n"
        'Answer with JSON only: {"labels": {"<observation id>": ["T....", ...], ...}}'
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="deepseek-v4-pro")
    parser.add_argument("--batch", type=int, default=10)
    args = parser.parse_args(argv)

    load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env")
    client = OpenAI(
        api_key=os.environ["DEEPSEEK_API_KEY"],
        base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
        timeout=600,
        max_retries=4,
    )
    candidates = candidate_list()
    valid_ids = {line.split(" | ")[0] for line in candidates.splitlines()}
    system = f"{GUIDELINE}\nCandidate techniques (ID | name | tactics):\n{candidates}"

    observations = load_observations()
    labels: dict[str, list[str]] = {}
    rejected: dict[str, list[str]] = {}
    usage = {"prompt_tokens": 0, "completion_tokens": 0, "calls": 0, "seconds": 0.0}
    raw_answers: list[str] = []
    served_model = None

    for start in range(0, len(observations), args.batch):
        batch = observations[start : start + args.batch]
        t0 = time.monotonic()
        response = client.chat.completions.create(
            model=args.model,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": _prompt(batch)}],
            max_tokens=16000,
        )
        usage["seconds"] += time.monotonic() - t0
        usage["calls"] += 1
        usage["prompt_tokens"] += response.usage.prompt_tokens
        usage["completion_tokens"] += response.usage.completion_tokens
        served_model = response.model
        content = response.choices[0].message.content or ""
        raw_answers.append(content)
        match = _JSON_RE.search(content)
        parsed = json.loads(match.group(0)).get("labels", {}) if match else {}
        for obs in batch:
            ids = [str(i).strip() for i in parsed.get(obs["id"], [])]
            labels[obs["id"]] = [i for i in ids if i in valid_ids][:3]
            bad = [i for i in ids if i not in valid_ids or not _ID_RE.match(i)]
            if bad:
                rejected[obs["id"]] = bad
        print(f"{start + len(batch)}/{len(observations)} labeled")

    LABELS_DIR.mkdir(parents=True, exist_ok=True)
    out = LABELS_DIR / "deepseek.json"
    out.write_text(
        json.dumps(
            {
                "labeler": "deepseek",
                "requested_model": args.model,
                "served_model": served_model,
                "labeled_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "usage": usage,
                "labels": labels,
                "rejected_ids": rejected,
                "raw_answers": raw_answers,
            },
            ensure_ascii=False,
            indent=1,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"Written {out} — usage {usage}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
