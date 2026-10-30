"""Retrieval eval of the ATT&CK layer: BM25 only vs dense only vs hybrid.

For every gold observation (evals/rag/gold.json) and each of its 3 phrasings
(terse / analyst / agent), each mode retrieves the top 10 techniques.

Metrics (mean over observation x phrasing):
  - Recall@k = |relevant ∩ top-k| / |relevant|, for k = 1 and 5;
  - Hit@k    = 1 if at least one relevant ID is in the top-k;
  - MRR      = 1 / rank of the first relevant ID (0 beyond rank 10);
each in two flavors: `strict` (exact ID) and `parent` (a retrieved
T1552.004 counts for a relevant T1552.001 — same parent technique).

Stability to rephrasing (per observation, then averaged): share of
observations whose 3 phrasings get the same top-1 technique, and mean
pairwise Jaccard of their top-5 sets.

Query embeddings go through a committed cache (evals/rag/embedding_cache/):
the first run calls mistral-embed, later runs replay offline (`--offline`).

Usage:
    python evals/rag/run_retrieval_eval.py            # writes evals/rag/results/
    python evals/rag/run_retrieval_eval.py --offline  # no API call (cache only)
"""

from __future__ import annotations

import argparse
import itertools
import json
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from evals.rag.labeling import GOLD, RAG_DIR, load_observations  # noqa: E402
from osintllm.rag.embeddings import CachedEmbedder, MistralEmbedder  # noqa: E402
from osintllm.rag.index import load_index  # noqa: E402
from osintllm.rag.retriever import MODES, AttackRetriever  # noqa: E402

PHRASINGS = ("terse", "analyst", "agent")
CACHE_DIR = RAG_DIR / "embedding_cache"
RESULTS_DIR = RAG_DIR / "results"
DEPTH = 10


def parent(attack_id: str) -> str:
    return attack_id.split(".")[0]


def score_ranking(retrieved: list[str], relevant: list[str], level) -> dict[str, float]:
    rel = {level(r) for r in relevant}
    got = [level(r) for r in retrieved]
    first = next((i for i, r in enumerate(got, start=1) if r in rel), None)
    out = {"mrr": 1.0 / first if first else 0.0}
    for k in (1, 5):
        top = set(got[:k])
        out[f"recall@{k}"] = len(rel & top) / len(rel)
        out[f"hit@{k}"] = 1.0 if rel & top else 0.0
    return out


def _mean(values: list[float]) -> float:
    return round(sum(values) / len(values), 3) if values else 0.0


def evaluate(retriever: AttackRetriever, gold: dict[str, list[str]], observations: list[dict]):
    per_query: list[dict] = []
    for obs in observations:
        if obs["id"] not in gold:
            continue
        for phrasing in PHRASINGS:
            query = obs["phrasings"][phrasing]
            for mode in MODES:
                t0 = time.monotonic()
                hits = retriever.search(query, k=DEPTH, mode=mode)
                per_query.append(
                    {
                        "id": obs["id"],
                        "category": obs["category"],
                        "phrasing": phrasing,
                        "mode": mode,
                        "query": query,
                        "relevant": gold[obs["id"]],
                        "retrieved": [h.attack_id for h in hits],
                        "seconds": round(time.monotonic() - t0, 4),
                    }
                )

    summary: dict[str, dict] = {}
    for mode in MODES:
        rows = [r for r in per_query if r["mode"] == mode]
        block: dict[str, dict] = {}
        for flavor, level in (("strict", lambda x: x), ("parent", parent)):
            scores = [score_ranking(r["retrieved"], r["relevant"], level) for r in rows]
            block[flavor] = {m: _mean([s[m] for s in scores]) for m in scores[0]} if scores else {}
        same_top1, jaccards = [], []
        for obs_id in {r["id"] for r in rows}:
            runs = [r["retrieved"] for r in rows if r["id"] == obs_id]
            same_top1.append(1.0 if len({r[0] if r else None for r in runs}) == 1 else 0.0)
            pair_j = [
                len(set(a[:5]) & set(b[:5])) / len(set(a[:5]) | set(b[:5]) or {None})
                for a, b in itertools.combinations(runs, 2)
            ]
            jaccards.append(sum(pair_j) / len(pair_j))
        block["stability"] = {
            "same_top1_across_phrasings": _mean(same_top1),
            "mean_top5_jaccard": _mean(jaccards),
        }
        block["by_phrasing_strict_hit@5"] = {
            p: _mean([score_ranking(r["retrieved"], r["relevant"], lambda x: x)["hit@5"]
                      for r in rows if r["phrasing"] == p])
            for p in PHRASINGS
        }
        summary[mode] = block
    return summary, per_query


def to_markdown(meta: dict, summary: dict) -> str:
    lines = [
        f"# ATT&CK retrieval eval — {meta['run_at']}",
        "",
        f"ATT&CK v{meta['attack_version']}, embeddings `{meta['embedding_model']}`, "
        f"{meta['observations']} gold observations x {len(PHRASINGS)} phrasings "
        f"= {meta['queries_per_mode']} queries per mode.",
        "",
        "| Mode | Recall@1 | Recall@5 | Hit@5 | MRR | Hit@5 (parent) | MRR (parent) "
        "| Same top-1 across phrasings | Top-5 Jaccard |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for mode, b in summary.items():
        s, p, st = b["strict"], b["parent"], b["stability"]
        lines.append(
            f"| {mode} | {s['recall@1']:.3f} | {s['recall@5']:.3f} | {s['hit@5']:.3f} "
            f"| {s['mrr']:.3f} | {p['hit@5']:.3f} | {p['mrr']:.3f} "
            f"| {st['same_top1_across_phrasings']:.3f} | {st['mean_top5_jaccard']:.3f} |"
        )
    lines += ["", "Strict Hit@5 by phrasing:", ""]
    for mode, b in summary.items():
        lines.append(f"- {mode}: " + ", ".join(
            f"{k} {v:.3f}" for k, v in b["by_phrasing_strict_hit@5"].items()))
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline", action="store_true", help="embedding cache only")
    args = parser.parse_args(argv)

    index = load_index()
    inner = None if args.offline else MistralEmbedder.from_env()
    embedder = CachedEmbedder(inner, CACHE_DIR, model=index.embedding_model,
                              offline=args.offline)
    retriever = AttackRetriever(index, embedder)
    gold_file = json.loads(GOLD.read_text(encoding="utf-8"))
    observations = load_observations()

    summary, per_query = evaluate(retriever, gold_file["gold"], observations)
    meta = {
        "run_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "attack_version": index.version,
        "embedding_model": index.embedding_model,
        "observations": gold_file["kept"],
        "excluded_observations": len(gold_file["excluded"]),
        "queries_per_mode": sum(1 for r in per_query if r["mode"] == "hybrid"),
        "embedding_cache": {"hits": embedder.hits, "misses": embedder.misses},
        "embedding_prompt_tokens": getattr(inner, "prompt_tokens", 0),
        "labeler_agreement": gold_file["agreement"],
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    (RESULTS_DIR / f"{stamp}.json").write_text(
        json.dumps({"meta": meta, "summary": summary, "per_query": per_query},
                   ensure_ascii=False, indent=1) + "\n",
        encoding="utf-8",
    )
    markdown = to_markdown(meta, summary)
    (RESULTS_DIR / f"{stamp}.md").write_text(markdown, encoding="utf-8")
    print(markdown)
    print(f"Results: evals/rag/results/{stamp}.{{json,md}}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
