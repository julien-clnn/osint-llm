"""Build the local MITRE ATT&CK index (`make attack-index`).

Downloads the pinned Enterprise STIX 2.1 bundle from `mitre-attack/
attack-stix-data`, keeps live techniques and sub-techniques, chunks them and
embeds every chunk with `mistral-embed`. The result lands in `data/attack/`
(see src/osintllm/rag/index.py for the layout) and is committed: the app and
the evals then work without rebuilding it.

Usage:
    python scripts/build_attack_index.py                    # pinned version, embeddings
    python scripts/build_attack_index.py --no-embed         # lexical-only index, no API key
    python scripts/build_attack_index.py --bundle file.json # local bundle (offline)
    python scripts/build_attack_index.py --version 20.0 --out data/attack

Requires MISTRAL_API_KEY (.env) unless --no-embed. Embedding the full corpus
is a one-off cost; the measured token count is printed and recorded in
`manifest.json`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import requests  # noqa: E402

from osintllm.rag.corpus import MAX_CHUNK_CHARS, build_chunks, parse_bundle  # noqa: E402
from osintllm.rag.embeddings import MistralEmbedder  # noqa: E402
from osintllm.rag.index import AttackIndex, default_index_dir  # noqa: E402

# Pinned ATT&CK release. Bump deliberately, rebuild, and note it in CHANGELOG.
ATTACK_VERSION = "20.0"
_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "v{version}/enterprise-attack/enterprise-attack-{version}.json"
)


def _load_bundle(version: str, local: Path | None) -> tuple[bytes, str]:
    """Bundle bytes + canonical source URL. A local copy is recorded under
    the official URL of its version: `source_sha256` is what proves which
    file was actually used."""
    url = _BUNDLE_URL.format(version=version)
    if local is not None:
        return local.read_bytes(), url
    print(f"Downloading {url} …")
    response = requests.get(url, timeout=120)
    response.raise_for_status()
    return response.content, url


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", default=ATTACK_VERSION)
    parser.add_argument("--bundle", type=Path, default=None, help="local STIX bundle")
    parser.add_argument("--out", type=Path, default=default_index_dir())
    parser.add_argument("--no-embed", action="store_true", help="lexical-only index")
    parser.add_argument("--max-chunk-chars", type=int, default=MAX_CHUNK_CHARS)
    args = parser.parse_args(argv)

    raw, source = _load_bundle(args.version, args.bundle)
    bundle = json.loads(raw)
    techniques = parse_bundle(bundle)
    chunks = build_chunks(techniques, args.max_chunk_chars)
    n_sub = sum(t.is_subtechnique for t in techniques)
    print(
        f"ATT&CK v{args.version}: {len(techniques)} techniques "
        f"({len(techniques) - n_sub} techniques + {n_sub} sub-techniques), "
        f"{len(chunks)} chunks"
    )

    manifest = {
        "attack_version": args.version,
        "domain": "enterprise-attack",
        "source": source,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "technique_count": len(techniques),
        "subtechnique_count": n_sub,
        "chunk_count": len(chunks),
        "max_chunk_chars": args.max_chunk_chars,
        "embedding_model": None,
        "embedding_dim": None,
        "embedding_prompt_tokens": None,
        "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

    embeddings = None
    if not args.no_embed:
        embedder = MistralEmbedder.from_env()
        print(f"Embedding {len(chunks)} chunks with {embedder.model} …")
        embeddings = embedder.embed([c.text for c in chunks])
        manifest.update(
            embedding_model=embedder.model,
            embedding_dim=int(embeddings.shape[1]),
            embedding_prompt_tokens=embedder.prompt_tokens,
        )
        print(f"Measured usage: {embedder.prompt_tokens} prompt tokens")

    index = AttackIndex(
        manifest=manifest,
        techniques={t.attack_id: t for t in techniques},
        chunks=chunks,
        embeddings=embeddings,
    )
    index.save(args.out)
    print(f"Index written to {args.out}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
