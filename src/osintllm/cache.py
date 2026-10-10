"""Simple disk cache for tool results.

Goal: avoid repeating the same external requests (WHOIS, crt.sh, ip-api)
during tests or repeated analyses. The cache sits at the tool level (see
tools/base.py), so it uniformly covers every source.

One entry = one JSON file `{ts, value}` in the cache directory, named after
the hash of (tool name + arguments). Configurable TTL.

Settings via environment variables (read dynamically):
  - OSINTLLM_NO_CACHE=1   disables the cache entirely
  - OSINTLLM_CACHE_DIR    cache directory (default: .cache)
  - OSINTLLM_CACHE_TTL    validity period in seconds (default: 86400 = 24 h)
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from contextvars import ContextVar
from pathlib import Path
from typing import Any

_DEFAULT_TTL = 86_400  # 24 hours


# Per-request override (API worker thread), takes precedence over the env.
_enabled_override: ContextVar[bool | None] = ContextVar("_enabled_override", default=None)


def set_enabled_override(enabled: bool | None) -> None:
    """Force the cache on/off for the current thread/context (None = use env)."""
    _enabled_override.set(enabled)


def _enabled() -> bool:
    override = _enabled_override.get()
    if override is not None:
        return override
    return os.getenv("OSINTLLM_NO_CACHE", "").lower() not in ("1", "true", "yes")


def _cache_dir() -> Path:
    directory = Path(os.getenv("OSINTLLM_CACHE_DIR", ".cache"))
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _ttl() -> int:
    try:
        return int(os.getenv("OSINTLLM_CACHE_TTL", str(_DEFAULT_TTL)))
    except ValueError:
        return _DEFAULT_TTL


def make_key(name: str, args: dict[str, Any]) -> str:
    """Stable key for a tool call (name + normalized arguments)."""
    payload = name + "|" + json.dumps(args, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def get(key: str) -> Any | None:
    """Return the cached value if present and not expired, else None."""
    if not _enabled():
        return None
    path = _cache_dir() / f"{key}.json"
    if not path.exists():
        return None
    try:
        entry = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None
    if time.time() - entry.get("ts", 0) > _ttl():
        return None
    return entry.get("value")


def set(key: str, value: Any) -> None:  # noqa: A001 — intentional get/set API
    """Store a value in the cache (no-op when the cache is disabled)."""
    if not _enabled():
        return
    path = _cache_dir() / f"{key}.json"
    try:
        path.write_text(
            json.dumps({"ts": time.time(), "value": value}, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError:
        pass  # a cache failure must never break an analysis
