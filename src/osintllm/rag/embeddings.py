"""Text embeddings for the ATT&CK retrieval layer.

An embedding turns a text into a vector whose direction encodes its meaning:
two texts that say the same thing with different words get close vectors.
That is what lets "AWS key found in a public GitHub repo" reach "Unsecured
Credentials" with almost no word in common.

  - `MistralEmbedder`: `mistral-embed` through the OpenAI-compatible
    `/v1/embeddings` endpoint, reusing the `openai` SDK already in the
    project. DeepSeek exposes no embedding model (checked on its `/models`
    endpoint), hence Mistral whatever the chat provider.
  - `HashingEmbedder`: deterministic, offline, no dependency — feature
    hashing of the tokens. Only meant for the tests (CI never calls an API);
    its "meaning" is lexical, never use it for a real index.
  - `CachedEmbedder`: disk cache keyed by (model, text). The retrieval eval
    commits its cache so that it replays offline; the agent uses a
    gitignored one, like the tool cache.

All vectors are returned L2-normalized (float32): a dot product is then a
cosine similarity.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Protocol

import numpy as np

from ..config import ConfigError, load_embedding_settings

# Inputs per request: well under Mistral's per-request token budget for
# chunks of ~300 tokens (see corpus.MAX_CHUNK_CHARS).
_BATCH_SIZE = 32

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def normalize(vectors: np.ndarray) -> np.ndarray:
    vectors = np.asarray(vectors, dtype=np.float32)
    norms = np.linalg.norm(vectors, axis=-1, keepdims=True)
    norms[norms == 0] = 1.0
    return vectors / norms


class Embedder(Protocol):
    model: str

    def embed(self, texts: list[str]) -> np.ndarray:
        """(len(texts), dim) float32 array, L2-normalized."""
        ...


class MistralEmbedder:
    """`mistral-embed` via the OpenAI-compatible endpoint."""

    def __init__(self, api_key: str, base_url: str, model: str, timeout: float = 30.0) -> None:
        from openai import OpenAI

        self.model = model
        self._client = OpenAI(api_key=api_key, base_url=base_url, timeout=timeout, max_retries=8)
        # Measured usage, read by the index build script and the evals.
        self.prompt_tokens = 0

    @classmethod
    def from_env(cls) -> "MistralEmbedder":
        """Raise ConfigError if MISTRAL_API_KEY is missing."""
        s = load_embedding_settings()
        return cls(api_key=s.api_key, base_url=s.base_url, model=s.model)

    def embed(self, texts: list[str]) -> np.ndarray:
        rows: list[list[float]] = []
        for start in range(0, len(texts), _BATCH_SIZE):
            batch = texts[start : start + _BATCH_SIZE]
            # encoding_format="float": the SDK otherwise asks for base64,
            # which is not part of Mistral's schema.
            response = self._client.embeddings.create(
                model=self.model, input=batch, encoding_format="float"
            )
            usage = getattr(response, "usage", None)
            self.prompt_tokens += getattr(usage, "prompt_tokens", 0) or 0
            rows.extend(item.embedding for item in sorted(response.data, key=lambda d: d.index))
        return normalize(np.array(rows, dtype=np.float32))


class HashingEmbedder:
    """Offline deterministic embedder for tests (see module docstring)."""

    def __init__(self, dim: int = 256) -> None:
        self.dim = dim
        self.model = f"hashing-{dim}"

    def _vector(self, text: str) -> np.ndarray:
        vec = np.zeros(self.dim, dtype=np.float32)
        for token in _TOKEN_RE.findall(text.lower()):
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            index = int.from_bytes(digest[:4], "little") % self.dim
            vec[index] += 1.0 if digest[4] % 2 else -1.0
        return vec

    def embed(self, texts: list[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, self.dim), dtype=np.float32)
        return normalize(np.stack([self._vector(t) for t in texts]))


def default_cache_dir() -> Path:
    return Path(os.getenv("OSINTLLM_EMBED_CACHE_DIR", ".cache/embeddings"))


class CachedEmbedder:
    """Disk cache in front of an embedder, one JSON file per (model, text).

    `offline=True` never calls the inner embedder: a cache miss raises
    `EmbeddingCacheMiss` (used to replay the retrieval eval without a key).
    """

    def __init__(
        self, inner: Embedder | None, cache_dir: Path, model: str | None = None,
        offline: bool = False,
    ) -> None:
        if inner is None and not offline:
            raise ValueError("an inner embedder is required unless offline=True")
        self.inner = inner
        self.model = model or (inner.model if inner is not None else "")
        self.cache_dir = Path(cache_dir)
        self.offline = offline
        self.hits = 0
        self.misses = 0

    def _path(self, text: str) -> Path:
        digest = hashlib.sha256(f"{self.model}\n{text}".encode("utf-8")).hexdigest()[:24]
        return self.cache_dir / f"{digest}.json"

    def _read(self, text: str) -> np.ndarray | None:
        path = self._path(text)
        if not path.exists():
            return None
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            return None
        if entry.get("model") != self.model or entry.get("text") != text:
            return None
        return np.frombuffer(base64.b64decode(entry["vector"]), dtype=np.float32)

    def _write(self, text: str, vector: np.ndarray) -> None:
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            payload = base64.b64encode(np.asarray(vector, dtype=np.float32).tobytes())
            self._path(text).write_text(
                json.dumps(
                    {"model": self.model, "text": text, "vector": payload.decode("ascii")},
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
        except OSError:
            pass  # a cache failure must never break a lookup

    def embed(self, texts: list[str]) -> np.ndarray:
        found: dict[int, np.ndarray] = {}
        missing: list[int] = []
        for i, text in enumerate(texts):
            vec = self._read(text)
            if vec is None:
                missing.append(i)
            else:
                found[i] = vec
        self.hits += len(found)
        self.misses += len(missing)
        if missing:
            if self.offline or self.inner is None:
                raise EmbeddingCacheMiss(
                    f"{len(missing)} text(s) not in the embedding cache {self.cache_dir} "
                    f"(model {self.model}); first: {texts[missing[0]]!r}"
                )
            fresh = self.inner.embed([texts[i] for i in missing])
            for i, vec in zip(missing, fresh):
                found[i] = vec
                self._write(texts[i], vec)
        if not texts:
            return np.zeros((0, 0), dtype=np.float32)
        return normalize(np.stack([found[i] for i in range(len(texts))]))


class EmbeddingCacheMiss(RuntimeError):
    """Offline cache miss (see `CachedEmbedder`)."""


def default_query_embedder() -> Embedder | None:
    """Embedder used by `attack_lookup` for queries: Mistral behind the
    gitignored disk cache, or None when no Mistral key is configured (the
    tool then falls back to lexical retrieval and says so)."""
    try:
        inner = MistralEmbedder.from_env()
    except ConfigError:
        return None
    return CachedEmbedder(inner, default_cache_dir())
