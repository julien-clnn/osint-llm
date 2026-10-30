"""ATT&CK retrieval: lexical (BM25), dense (cosine on embeddings) or hybrid.

Retrieval runs on CHUNKS, results are returned per TECHNIQUE: a technique
scores as its best chunk, and that chunk provides the excerpt.

Hybrid = reciprocal rank fusion (RRF, Cormack et al. 2009) of the two chunk
rankings: score(c) = sum over rankings of 1 / (RRF_K + rank(c)). RRF only
uses ranks, so the two scores (BM25 unbounded, cosine in [-1, 1]) never have
to be calibrated against each other. Each ranking is cut at `CANDIDATES`
chunks, and a chunk with a zero BM25 score (no query term) gets no lexical
credit.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

import numpy as np

from .bm25 import BM25
from .embeddings import Embedder
from .index import AttackIndex

MODES = ("bm25", "dense", "hybrid")
RRF_K = 60  # the usual constant from the RRF paper
CANDIDATES = 100
EXCERPT_CHARS = 300


@dataclass
class TechniqueHit:
    attack_id: str
    name: str
    tactics: list[str]
    url: str
    score: float
    excerpt: str
    chunk_id: str
    ranks: dict[str, int | None] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RetrievalUnavailable(RuntimeError):
    """The requested mode cannot run (no embeddings or no embedder)."""


def _rank(scores: np.ndarray, keep: np.ndarray | None = None) -> dict[int, int]:
    """Chunk row -> 1-based rank, best first, cut at CANDIDATES."""
    order = np.argsort(-scores, kind="stable")
    if keep is not None:
        order = order[keep[order]]
    return {int(row): r for r, row in enumerate(order[:CANDIDATES], start=1)}


class AttackRetriever:
    def __init__(self, index: AttackIndex, embedder: Embedder | None = None) -> None:
        self.index = index
        self.embedder = embedder
        self._bm25 = BM25([c.text for c in index.chunks])

    def can_dense(self) -> bool:
        return self.index.embeddings is not None and self.embedder is not None

    def _dense_scores(self, query: str) -> np.ndarray:
        if not self.can_dense():
            raise RetrievalUnavailable(
                "dense retrieval needs an index with embeddings and a query embedder"
            )
        expected = self.index.embedding_model
        if expected and self.embedder.model != expected:
            raise RetrievalUnavailable(
                f"query embedder {self.embedder.model!r} differs from the index "
                f"model {expected!r}: vectors would not be comparable"
            )
        vector = self.embedder.embed([query])[0]
        return self.index.embeddings @ vector

    def search(self, query: str, k: int = 5, mode: str = "hybrid") -> list[TechniqueHit]:
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode!r} (expected one of {MODES})")

        rankings: dict[str, dict[int, int]] = {}
        if mode in ("bm25", "hybrid"):
            lexical = self._bm25.scores(query)
            rankings["bm25"] = _rank(lexical, keep=lexical > 0)
        if mode in ("dense", "hybrid"):
            rankings["dense"] = _rank(self._dense_scores(query))

        if mode == "hybrid":
            chunk_scores: dict[int, float] = {}
            for ranking in rankings.values():
                for row, r in ranking.items():
                    chunk_scores[row] = chunk_scores.get(row, 0.0) + 1.0 / (RRF_K + r)
        else:
            # Single ranking: the score is 1/rank-based too, so that scores
            # stay comparable in spirit across modes (higher = better).
            (ranking,) = rankings.values()
            chunk_scores = {row: 1.0 / (RRF_K + r) for row, r in ranking.items()}

        best: dict[str, tuple[float, int]] = {}
        for row, score in chunk_scores.items():
            attack_id = self.index.chunks[row].attack_id
            if attack_id not in best or score > best[attack_id][0]:
                best[attack_id] = (score, row)

        ordered = sorted(best.items(), key=lambda kv: (-kv[1][0], kv[0]))[:k]
        hits: list[TechniqueHit] = []
        for attack_id, (score, row) in ordered:
            chunk = self.index.chunks[row]
            technique = self.index.techniques[attack_id]
            body = chunk.text.split("\n", 1)[1] if "\n" in chunk.text else chunk.text
            hits.append(
                TechniqueHit(
                    attack_id=attack_id,
                    name=technique.name,
                    tactics=list(technique.tactics),
                    url=technique.url,
                    score=round(float(score), 6),
                    excerpt=body[:EXCERPT_CHARS],
                    chunk_id=chunk.chunk_id,
                    ranks={name: ranking.get(row) for name, ranking in rankings.items()},
                )
            )
        return hits
