"""ATT&CK lookup tool — maps an observation to MITRE ATT&CK techniques.

The agent describes its findings in short sentences ("DMARC policy is
p=none, SPF ends with ~all"); for each one, the tool retrieves the closest ATT&CK Enterprise
techniques from the local index (data/attack/, see src/osintllm/rag/) and
returns their ID, name, tactics and a short excerpt of the official text.
The report may then cite ONLY technique IDs returned here: the
investigation enforces it deterministically (see investigation.py).

Retrieval is hybrid (BM25 + mistral-embed, RRF; measured in docs/RAG.md).
Without MISTRAL_API_KEY, or if the embedding call fails, it falls back to
BM25 alone and says so in the `retrieval` field.

PASSIVE and fully local apart from the query embedding: nothing touches the
target. Not replayable from fixtures (see Tool.replayable): its argument is
free text written by the LLM, and its result is already deterministic for a
given query.
"""

from __future__ import annotations

from typing import Any

from ..rag.embeddings import default_query_embedder
from ..rag.index import load_index
from ..rag.retriever import AttackRetriever
from .base import Tool, cap_text

DEFAULT_K = 5
MAX_K = 8
MAX_OBSERVATIONS = 8
# Excerpt length sent to the LLM. The tool output is re-sent in every later
# LLM call of the run (verifier included), so it drives the layer's token
# overhead; 200 characters keep the opening sentence of the technique.
_EXCERPT_CHARS = 200
_MAX_QUERY_CHARS = 300

_retriever: AttackRetriever | None = None


def _get_retriever() -> AttackRetriever:
    """Built once per process: loading the index takes ~1-2 s."""
    global _retriever
    if _retriever is None:
        _retriever = AttackRetriever(load_index(), default_query_embedder())
    return _retriever


def set_retriever(retriever: AttackRetriever | None) -> None:
    """Swap the retriever (tests: mini corpus + offline embedder)."""
    global _retriever
    _retriever = retriever


def _lookup_one(retriever: AttackRetriever, observation: str, k: int) -> dict[str, Any]:
    query = cap_text(observation.strip(), _MAX_QUERY_CHARS)
    retrieval = "hybrid"
    if not retriever.can_dense():
        retrieval = "bm25 (no embedding key or no embeddings in the index)"
        hits = retriever.search(query, k=k, mode="bm25")
    else:
        try:
            hits = retriever.search(query, k=k, mode="hybrid")
        except Exception as exc:  # noqa: BLE001 — embedding API down: degrade, don't fail
            retrieval = f"bm25 (embedding failed: {type(exc).__name__})"
            hits = retriever.search(query, k=k, mode="bm25")
    return {
        "observation": query,
        "retrieval": retrieval,
        "techniques": [
            # No URL (derived from the ID by the report and the UI) and no
            # score (meaningless to the model): fewer tokens per call.
            {
                "attack_id": h.attack_id,
                "name": h.name,
                "tactics": h.tactics,
                "excerpt": h.excerpt[:_EXCERPT_CHARS],
            }
            for h in hits
        ],
    }


def attack_lookup(observations: list[str], k: int = DEFAULT_K) -> dict[str, Any]:
    """Return, for each observation, the closest ATT&CK techniques.

    One call takes ALL the findings to map (at most `MAX_OBSERVATIONS`): the
    tool then costs a single step of the agent loop, whatever the number of
    findings (the loop has a hard iteration budget, see agent.py).

    Args:
        observations: short descriptions, one finding each.
        k: techniques per observation (1 to 8, default 5).

    Returns:
        {"attack_version", "results": [{"observation", "retrieval",
        "techniques": [...]}, ...]} or {"error": ...}.
    """
    if isinstance(observations, str):
        observations = [observations]
    if not isinstance(observations, list):
        return {"error": "observations must be a list of strings"}
    items = [o for o in observations if isinstance(o, str) and o.strip()]
    if not items:
        return {"error": "observations must contain at least one non-empty string"}
    try:
        k = max(1, min(MAX_K, int(k)))
    except (TypeError, ValueError):
        k = DEFAULT_K

    retriever = _get_retriever()
    result: dict[str, Any] = {
        "attack_version": retriever.index.version,
        "results": [_lookup_one(retriever, o, k) for o in items[:MAX_OBSERVATIONS]],
    }
    if len(items) > MAX_OBSERVATIONS:
        result["truncated"] = f"only the first {MAX_OBSERVATIONS} observations were looked up"
    return result


attack_lookup_tool = Tool(
    name="attack_lookup",
    description=(
        "Searches the MITRE ATT&CK Enterprise knowledge base (local index) for "
        "the techniques that best match the observations you made with the other "
        "tools, e.g. 'DMARC policy is p=none and SPF ends with ~all' or 'domain "
        "registered 25 days ago, flagged by 14 VirusTotal engines'. Returns "
        "technique IDs, names, tactics and an excerpt of the official text. Call "
        "it ONCE, after collecting the facts, with all the notable findings as a "
        "list. You may only cite ATT&CK technique IDs returned by this tool."
    ),
    parameters={
        "type": "object",
        "properties": {
            "observations": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    f"The notable findings (max {MAX_OBSERVATIONS}), one concrete "
                    "finding per item, each in one short sentence."
                ),
            },
            "k": {
                "type": "integer",
                "description": f"Number of techniques to return (default {DEFAULT_K}, "
                f"max {MAX_K}).",
            },
        },
        "required": ["observations"],
    },
    func=attack_lookup,
    replayable=False,
)
