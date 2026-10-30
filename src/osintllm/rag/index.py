"""The ATT&CK index on disk: plain files, no vector database server.

Layout of an index directory (default `data/attack/`):
  - `manifest.json`   ATT&CK version, source URL + sha256 of the bundle,
                      embedding model, counts, build date;
  - `techniques.json` one entry per technique (see corpus.Technique);
  - `chunks.json`     the retrievable chunks, in the row order of the matrix;
  - `embeddings.npy`  (n_chunks, dim) matrix, float16 on disk (halves the
                      size, no measurable effect on cosine ranking at this
                      scale), float32 L2-normalized once loaded. Absent for
                      an index built with `--no-embed` (lexical only).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import numpy as np

from .corpus import Chunk, Technique
from .embeddings import normalize

MANIFEST = "manifest.json"
TECHNIQUES = "techniques.json"
CHUNKS = "chunks.json"
EMBEDDINGS = "embeddings.npy"


def default_index_dir() -> Path:
    return Path(os.getenv("OSINTLLM_ATTACK_INDEX_DIR", "data/attack"))


class IndexMissingError(RuntimeError):
    """No index at the expected location (run `make attack-index`)."""


@dataclass
class AttackIndex:
    manifest: dict[str, Any]
    techniques: dict[str, Technique]
    chunks: list[Chunk]
    embeddings: np.ndarray | None = None
    _row_by_chunk: dict[str, int] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if self.embeddings is not None and len(self.embeddings) != len(self.chunks):
            raise ValueError(
                f"{len(self.embeddings)} embeddings for {len(self.chunks)} chunks"
            )

    @property
    def version(self) -> str:
        return str(self.manifest.get("attack_version", "?"))

    @property
    def embedding_model(self) -> str | None:
        return self.manifest.get("embedding_model") if self.embeddings is not None else None

    def save(self, directory: Path) -> None:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        _write_json(directory / MANIFEST, self.manifest)
        _write_json(
            directory / TECHNIQUES,
            [t.to_dict() for t in sorted(self.techniques.values(), key=lambda t: t.attack_id)],
        )
        _write_json(directory / CHUNKS, [c.to_dict() for c in self.chunks])
        if self.embeddings is not None:
            np.save(directory / EMBEDDINGS, self.embeddings.astype(np.float16))
        elif (directory / EMBEDDINGS).exists():
            (directory / EMBEDDINGS).unlink()

    @classmethod
    def load(cls, directory: Path) -> "AttackIndex":
        directory = Path(directory)
        if not (directory / MANIFEST).exists():
            raise IndexMissingError(
                f"No ATT&CK index in {directory} — build it with `make attack-index`."
            )
        manifest = json.loads((directory / MANIFEST).read_text(encoding="utf-8"))
        techniques = [
            Technique.from_dict(d)
            for d in json.loads((directory / TECHNIQUES).read_text(encoding="utf-8"))
        ]
        chunks = [
            Chunk.from_dict(d)
            for d in json.loads((directory / CHUNKS).read_text(encoding="utf-8"))
        ]
        embeddings = None
        if (directory / EMBEDDINGS).exists():
            embeddings = normalize(np.load(directory / EMBEDDINGS).astype(np.float32))
        return cls(
            manifest=manifest,
            techniques={t.attack_id: t for t in techniques},
            chunks=chunks,
            embeddings=embeddings,
        )


@lru_cache(maxsize=4)
def load_index(directory: str | None = None) -> AttackIndex:
    """Loaded once per process (the tool is called several times per run)."""
    return AttackIndex.load(Path(directory) if directory else default_index_dir())


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
