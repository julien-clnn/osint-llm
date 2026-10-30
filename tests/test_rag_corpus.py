"""ATT&CK corpus ingestion, chunking and on-disk index (no network, no key).

Runs on `tests/fixtures/attack_mini_bundle.json`, a tiny hand-written
ATT&CK-shaped bundle (abridged texts) covering the cases that matter:
techniques, sub-techniques, revoked/deprecated objects, citations, markdown
links and a detection strategy.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from osintllm.rag.corpus import Technique, build_chunks, chunk_technique, clean_text, parse_bundle
from osintllm.rag.embeddings import CachedEmbedder, EmbeddingCacheMiss, HashingEmbedder
from osintllm.rag.index import AttackIndex

MINI_BUNDLE = Path(__file__).parent / "fixtures" / "attack_mini_bundle.json"


def _techniques() -> list[Technique]:
    return parse_bundle(json.loads(MINI_BUNDLE.read_text(encoding="utf-8")))


def test_parse_skips_revoked_and_deprecated():
    ids = [t.attack_id for t in _techniques()]
    assert "T1999" not in ids and "T1998" not in ids
    assert ids == sorted(ids)
    assert len(ids) == 8


def test_subtechnique_name_includes_parent():
    by_id = {t.attack_id: t for t in _techniques()}
    assert by_id["T1552.001"].name == "Unsecured Credentials: Credentials In Files"
    assert by_id["T1552.001"].is_subtechnique
    assert by_id["T1552"].name == "Unsecured Credentials"


def test_tactics_platforms_url_and_detection():
    t = {t.attack_id: t for t in _techniques()}["T1566"]
    assert t.tactics == ["Initial Access"]
    assert t.platforms == ["Linux", "Windows"]
    assert t.url == "https://attack.mitre.org/techniques/T1566"
    assert t.detection == ["Detection of Spoofed Sender Domains in Inbound E-mail"]


def test_clean_text_strips_citations_links_and_code_tags():
    raw = "See [the guide](https://x.org) and <code>AWS</code> keys. (Citation: Foo Bar)\n\n\nNext."
    assert clean_text(raw) == "See the guide and AWS keys.\n\nNext."


def test_every_chunk_keeps_id_and_name():
    long = Technique(
        attack_id="T0001", name="Long One", tactics=["Reconnaissance"], platforms=[],
        url="u", description="\n\n".join(f"Sentence number {i} about things." * 8
                                         for i in range(12)),
        detection=["Strategy A"],
    )
    chunks = chunk_technique(long, max_chars=400)
    assert len(chunks) > 3
    assert all(c.text.startswith("T0001 Long One (tactics: Reconnaissance)") for c in chunks)
    assert all(len(c.text) <= 400 for c in chunks)
    assert chunks[-1].kind == "detection"
    assert [c.chunk_id for c in chunks] == [f"T0001#{i}" for i in range(len(chunks))]


def test_index_roundtrip(tmp_path):
    techniques = _techniques()
    chunks = build_chunks(techniques)
    vectors = HashingEmbedder().embed([c.text for c in chunks])
    index = AttackIndex(
        manifest={"attack_version": "mini", "embedding_model": "hashing-256"},
        techniques={t.attack_id: t for t in techniques},
        chunks=chunks,
        embeddings=vectors,
    )
    index.save(tmp_path)
    loaded = AttackIndex.load(tmp_path)
    assert loaded.version == "mini"
    assert [c.chunk_id for c in loaded.chunks] == [c.chunk_id for c in chunks]
    assert loaded.techniques["T1566"].detection == [
        "Detection of Spoofed Sender Domains in Inbound E-mail"
    ]
    # float16 on disk: the ranking must survive the round trip.
    query = HashingEmbedder().embed(["AWS access keys in public repositories"])[0]
    assert np.argmax(loaded.embeddings @ query) == np.argmax(vectors @ query)


def test_cached_embedder_offline_replay(tmp_path):
    inner = HashingEmbedder()
    online = CachedEmbedder(inner, tmp_path)
    first = online.embed(["DMARC p=none"])
    offline = CachedEmbedder(None, tmp_path, model=inner.model, offline=True)
    assert np.allclose(offline.embed(["DMARC p=none"]), first)
    try:
        offline.embed(["never seen"])
    except EmbeddingCacheMiss:
        pass
    else:
        raise AssertionError("offline cache miss must raise")
