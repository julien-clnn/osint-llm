"""Record/replay mode for tool results, for a deterministic, offline eval
harness.

Distinct from the disk cache (`cache.py`): the cache is a best-effort
optimization with a TTL, never committed. Fixtures are an eval artifact
versioned in the repo (`evals/fixtures/<domain>/`), with no expiry, read
identically on every replay.

Hooked at the same point as the cache — `Tool.run()` (see tools/base.py) —
rather than in the HTTP client (`http.py`): some tools (whois_lookup via the
`python-whois` lib, DNS/IP resolution) never go through `http.py`.
`Tool.run()` is the only choke point shared by all tools, whatever their
underlying network transport.

Three modes, driven by `OSINTLLM_FIXTURE_MODE`:
  - (unset): normal behavior, best-effort cache (see cache.py).
  - "record": bypasses cache reads, really runs each tool and saves EVERY
    result (success or error) to disk.
  - "replay": serves ONLY fixtures. A missing fixture raises
    `FixtureMissError` — never a silent network fallback.

The current domain is needed to index fixtures (a tool's arguments don't
always carry the domain, e.g. asn_lookup takes an IP). It is set via
`set_current_domain()` by the run's caller (agent, CLI or eval harness),
through a ContextVar: each thread/task keeps its own value, which stays
correct even when the API serves several analyses in parallel (one worker
thread per request, see api.py).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from contextvars import ContextVar
from pathlib import Path
from typing import Any

FIXTURES_ROOT = Path(os.getenv("OSINTLLM_FIXTURES_DIR", "evals/fixtures"))

_current_domain: ContextVar[str | None] = ContextVar("_current_domain", default=None)


class FixtureMissError(RuntimeError):
    """Raised in replay mode when no fixture matches the call."""


def _mode() -> str | None:
    value = os.getenv("OSINTLLM_FIXTURE_MODE", "").strip().lower()
    return value or None


def recording() -> bool:
    return _mode() == "record"


def replaying() -> bool:
    return _mode() == "replay"


def set_current_domain(domain: str) -> None:
    """Call before any tool execution to scope fixtures."""
    _current_domain.set(domain.strip().lower())


def _active_domain() -> str:
    domain = _current_domain.get()
    if domain is None:
        raise RuntimeError(
            "No active domain for fixtures — call "
            "fixtures.set_current_domain(domain) before running a tool "
            "in --record/--replay mode."
        )
    return domain


def _safe_dirname(domain: str) -> str:
    return re.sub(r"[^a-z0-9.-]", "_", domain.lower())


def _domain_dir(domain: str) -> Path:
    directory = FIXTURES_ROOT / _safe_dirname(domain)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _fixture_path(domain: str, tool_name: str, args: dict[str, Any]) -> Path:
    payload = json.dumps(args, sort_keys=True, ensure_ascii=False)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    return _domain_dir(domain) / f"{tool_name}__{digest}.json"


def load(tool_name: str, args: dict[str, Any]) -> Any:
    """Replay mode: load the tool's fixture, or raise `FixtureMissError`."""
    domain = _active_domain()
    path = _fixture_path(domain, tool_name, args)
    if not path.exists():
        raise FixtureMissError(
            f"Missing fixture for {tool_name}({args!r}) — domain "
            f"{domain!r} (expected: {path}). No network fallback in "
            "--replay mode; record it first with --record."
        )
    entry = json.loads(path.read_text(encoding="utf-8"))
    return entry["result"]


def save(tool_name: str, args: dict[str, Any], result: Any) -> None:
    """Record mode: save the tool's real result to disk."""
    domain = _active_domain()
    path = _fixture_path(domain, tool_name, args)
    path.write_text(
        json.dumps(
            {"tool": tool_name, "arguments": args, "result": result},
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
