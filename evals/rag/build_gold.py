"""Merge the two independent labelings into the gold set (evals/rag/gold.json).

Rule: the relevant IDs of an observation are the IDs BOTH labelers gave
(intersection). An observation where they share no ID is excluded from the
retrieval metrics and listed under `excluded` with both labelings, so that
the disagreement stays visible instead of being silently arbitrated.

Inter-labeler agreement is published alongside:
  - top-1 agreement: same first ID;
  - overlap: at least one common ID (= kept observations);
  - mean Jaccard of the two ID sets;
  - the same three at parent-technique level (T1552.001 -> T1552).

Usage:
    python evals/rag/build_gold.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from evals.rag.labeling import GOLD, LABELS_DIR, load_observations  # noqa: E402

LABELERS = ("deepseek", "claude")


def parent(attack_id: str) -> str:
    return attack_id.split(".")[0]


def _jaccard(a: set[str], b: set[str]) -> float:
    return len(a & b) / len(a | b) if a | b else 1.0


def agreement(pairs: list[tuple[list[str], list[str]]], level=lambda x: x) -> dict:
    n = len(pairs) or 1
    top1 = sum(bool(a and b and level(a[0]) == level(b[0])) for a, b in pairs)
    overlap = sum(bool({level(x) for x in a} & {level(x) for x in b}) for a, b in pairs)
    jac = sum(_jaccard({level(x) for x in a}, {level(x) for x in b}) for a, b in pairs)
    return {
        "top1_agreement": round(top1 / n, 3),
        "overlap_rate": round(overlap / n, 3),
        "mean_jaccard": round(jac / n, 3),
    }


def main() -> int:
    labelings = {
        name: json.loads((LABELS_DIR / f"{name}.json").read_text(encoding="utf-8"))
        for name in LABELERS
    }
    observations = load_observations()
    gold: dict[str, list[str]] = {}
    excluded: dict[str, dict[str, list[str]]] = {}
    pairs = []
    for obs in observations:
        a = labelings["deepseek"]["labels"].get(obs["id"], [])
        b = labelings["claude"]["labels"].get(obs["id"], [])
        pairs.append((a, b))
        common = [x for x in a if x in set(b)]
        if common:
            gold[obs["id"]] = common
        else:
            excluded[obs["id"]] = {"deepseek": a, "claude": b}

    result = {
        "rule": "relevant IDs = intersection of the two labelings; empty -> excluded",
        "labelers": {
            name: {k: data.get(k) for k in ("labeler", "requested_model", "served_model")}
            for name, data in labelings.items()
        },
        "agreement": {
            "observations": len(observations),
            "exact": agreement(pairs),
            "parent_level": agreement(pairs, parent),
        },
        "kept": len(gold),
        "gold": gold,
        "excluded": excluded,
    }
    GOLD.write_text(json.dumps(result, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(result["agreement"], indent=1))
    print(f"kept {len(gold)}/{len(observations)} observations -> {GOLD}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
