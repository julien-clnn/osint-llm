"""Retrieval on the mini ATT&CK corpus: BM25, dense (offline hashing
embedder) and hybrid RRF. No network, no key."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from osintllm.rag.bm25 import BM25, tokenize
from osintllm.rag.corpus import build_chunks, parse_bundle
from osintllm.rag.embeddings import HashingEmbedder
from osintllm.rag.index import AttackIndex
from osintllm.rag.retriever import AttackRetriever, RetrievalUnavailable

MINI_BUNDLE = Path(__file__).parent / "fixtures" / "attack_mini_bundle.json"


def mini_index(with_embeddings: bool = True) -> AttackIndex:
    techniques = parse_bundle(json.loads(MINI_BUNDLE.read_text(encoding="utf-8")))
    chunks = build_chunks(techniques)
    embedder = HashingEmbedder()
    return AttackIndex(
        manifest={"attack_version": "mini", "embedding_model": embedder.model},
        techniques={t.attack_id: t for t in techniques},
        chunks=chunks,
        embeddings=embedder.embed([c.text for c in chunks]) if with_embeddings else None,
    )


def test_tokenize_keeps_dotted_terms_and_drops_stopwords():
    assert tokenize("The DMARC p=none policy of example.com") == [
        "dmarc", "p", "none", "policy", "example.com"
    ]


def test_bm25_prefers_documents_with_rare_query_terms():
    bm25 = BM25(["dmarc policy missing", "generic text about policy", "nothing here"])
    scores = bm25.scores("dmarc policy")
    assert scores[0] > scores[1] > scores[2] == 0


@pytest.mark.parametrize("mode", ["bm25", "dense", "hybrid"])
def test_each_mode_finds_the_obvious_technique(mode):
    retriever = AttackRetriever(mini_index(), HashingEmbedder())
    hits = retriever.search("AWS access keys found in public source code repositories",
                            k=3, mode=mode)
    assert hits[0].attack_id == "T1552.001"
    assert hits[0].name == "Unsecured Credentials: Credentials In Files"
    assert "credentials" in hits[0].excerpt.lower()


def test_hits_are_unique_per_technique_and_sorted():
    retriever = AttackRetriever(mini_index(), HashingEmbedder())
    hits = retriever.search("phishing e-mail DMARC spoofing", k=5)
    ids = [h.attack_id for h in hits]
    assert len(ids) == len(set(ids))
    assert [h.score for h in hits] == sorted((h.score for h in hits), reverse=True)
    assert hits[0].attack_id == "T1566"
    assert set(hits[0].ranks) == {"bm25", "dense"}


def test_dense_without_embedder_is_refused():
    retriever = AttackRetriever(mini_index(), embedder=None)
    with pytest.raises(RetrievalUnavailable):
        retriever.search("phishing", mode="dense")
    # Lexical retrieval keeps working.
    assert retriever.search("phishing", mode="bm25")[0].attack_id.startswith("T1566")


def test_embedder_model_mismatch_is_refused():
    retriever = AttackRetriever(mini_index(), HashingEmbedder(dim=128))
    with pytest.raises(RetrievalUnavailable):
        retriever.search("phishing", mode="hybrid")
