"""ATT&CK Enterprise corpus — from the STIX 2.1 bundle to retrievable chunks.

Source: `mitre-attack/attack-stix-data` (GitHub), `enterprise-attack-<v>.json`.
Only `attack-pattern` objects (techniques and sub-techniques) are kept,
minus revoked and deprecated ones.

Detection text: since ATT&CK v18 the `x_mitre_detection` free-text field is
gone; detection lives in `x-mitre-detection-strategy` objects linked to a
technique by a `detects` relationship. We keep only the strategy NAMES (one
line each): the underlying analytics describe endpoint telemetry (process
lineage, Windows events…), off-topic for passive domain reconnaissance and
noisy for retrieval.

Chunking: descriptions are packed paragraph by paragraph into chunks of at
most `MAX_CHUNK_CHARS` characters; every chunk starts with a header line
(ID, full name, tactics) so that it stays self-contained once retrieved
alone. The detection strategies form a separate chunk.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

# ~300 tokens: long enough to keep a paragraph's context, short enough that
# one technique's long description doesn't dilute its dense vector.
MAX_CHUNK_CHARS = 1200

_CITATION_RE = re.compile(r"\(Citation:[^)]*\)")
_MD_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_HTML_TAG_RE = re.compile(r"</?code>")
_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+")


@dataclass
class Technique:
    """One ATT&CK technique or sub-technique."""

    attack_id: str
    name: str  # full name, "Parent: Sub" for a sub-technique
    tactics: list[str]
    platforms: list[str]
    url: str
    description: str
    detection: list[str] = field(default_factory=list)
    is_subtechnique: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Technique":
        return cls(**data)


@dataclass
class Chunk:
    """A retrievable unit of text, always tied to one technique."""

    chunk_id: str  # "<attack_id>#<n>"
    attack_id: str
    kind: str  # "description" | "detection"
    text: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Chunk":
        return cls(**data)


def clean_text(text: str) -> str:
    """Strip STIX markup that only adds noise for retrieval: citation
    markers, markdown links (the label is kept), `<code>` tags."""
    text = _CITATION_RE.sub("", text or "")
    text = _MD_LINK_RE.sub(r"\1", text)
    text = _HTML_TAG_RE.sub("", text)
    paragraphs = [re.sub(r"[ \t]+", " ", p).strip() for p in re.split(r"\n\s*\n", text)]
    return "\n\n".join(p for p in paragraphs if p)


def _attack_ref(obj: dict[str, Any]) -> dict[str, Any] | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref
    return None


def _is_live(obj: dict[str, Any]) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def parse_bundle(bundle: dict[str, Any]) -> list[Technique]:
    """Extract the live techniques of a STIX bundle, sorted by ATT&CK ID."""
    objects = bundle.get("objects", [])
    by_stix_id = {o["id"]: o for o in objects if "id" in o}

    tactic_names = {
        o["x_mitre_shortname"]: o["name"]
        for o in objects
        if o.get("type") == "x-mitre-tactic" and "x_mitre_shortname" in o
    }

    detections: dict[str, list[str]] = {}
    for rel in objects:
        if rel.get("type") != "relationship" or rel.get("relationship_type") != "detects":
            continue
        source = by_stix_id.get(rel.get("source_ref", ""))
        if source is None or source.get("type") != "x-mitre-detection-strategy":
            continue
        if not _is_live(source):
            continue
        detections.setdefault(rel["target_ref"], []).append(source["name"])

    raw: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for obj in objects:
        if obj.get("type") != "attack-pattern" or not _is_live(obj):
            continue
        ref = _attack_ref(obj)
        if ref is not None:
            raw.append((obj, ref))

    names_by_id = {ref["external_id"]: obj["name"] for obj, ref in raw}

    techniques: list[Technique] = []
    for obj, ref in raw:
        attack_id = ref["external_id"]
        name = obj["name"]
        is_sub = bool(obj.get("x_mitre_is_subtechnique"))
        if is_sub:
            parent = names_by_id.get(attack_id.split(".")[0])
            if parent:
                name = f"{parent}: {name}"
        tactics = [
            tactic_names.get(p["phase_name"], p["phase_name"])
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        techniques.append(
            Technique(
                attack_id=attack_id,
                name=name,
                tactics=tactics,
                platforms=list(obj.get("x_mitre_platforms", [])),
                url=ref.get("url", f"https://attack.mitre.org/techniques/{attack_id}"),
                description=clean_text(obj.get("description", "")),
                detection=sorted(set(detections.get(obj["id"], []))),
                is_subtechnique=is_sub,
            )
        )
    techniques.sort(key=lambda t: t.attack_id)
    return techniques


def _header(t: Technique) -> str:
    tactics = ", ".join(t.tactics) or "n/a"
    return f"{t.attack_id} {t.name} (tactics: {tactics})"


def _split_long(paragraph: str, limit: int) -> list[str]:
    """Split a paragraph longer than `limit` on sentence boundaries."""
    if len(paragraph) <= limit:
        return [paragraph]
    parts: list[str] = []
    current = ""
    for sentence in _SENTENCE_RE.split(paragraph):
        if current and len(current) + 1 + len(sentence) > limit:
            parts.append(current)
            current = sentence
        else:
            current = f"{current} {sentence}".strip()
    if current:
        parts.append(current)
    # A single sentence longer than the limit is hard-cut as a last resort.
    return [p[i : i + limit] for p in parts for i in range(0, len(p), limit)]


def chunk_technique(t: Technique, max_chars: int = MAX_CHUNK_CHARS) -> list[Chunk]:
    """Cut a technique into self-contained chunks (header line in each)."""
    header = _header(t)
    budget = max(200, max_chars - len(header) - 1)

    pieces: list[str] = []
    for paragraph in t.description.split("\n\n"):
        pieces.extend(_split_long(paragraph, budget))

    bodies: list[str] = []
    current = ""
    for piece in pieces:
        if current and len(current) + 2 + len(piece) > budget:
            bodies.append(current)
            current = piece
        else:
            current = f"{current}\n\n{piece}" if current else piece
    if current:
        bodies.append(current)
    if not bodies:
        bodies = [""]

    chunks = [
        Chunk(f"{t.attack_id}#{i}", t.attack_id, "description", f"{header}\n{body}".strip())
        for i, body in enumerate(bodies)
    ]
    if t.detection:
        chunks.append(
            Chunk(
                f"{t.attack_id}#{len(chunks)}",
                t.attack_id,
                "detection",
                f"{header}\nDetection strategies: " + "; ".join(t.detection),
            )
        )
    return chunks


def build_chunks(techniques: list[Technique], max_chars: int = MAX_CHUNK_CHARS) -> list[Chunk]:
    return [c for t in techniques for c in chunk_technique(t, max_chars)]
