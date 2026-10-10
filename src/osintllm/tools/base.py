"""Common foundation for the OSINT tools.

Each tool exposes:
  - a unique `name`,
  - a `description` (read by the LLM to decide when to call it),
  - a JSON schema of its parameters (OpenAI function-calling format),
  - a `run(**kwargs)` method that actually performs the action and returns
    a JSON-serializable dict.

Almost all tools are PASSIVE: they only query public third-party sources,
never the target. The one deliberate exception, `tech_fingerprint`, sends ONE
lightweight HTTP request (headers) to the domain's home page.
"""

from __future__ import annotations

from typing import Any, Callable

from .. import cache, fixtures
from ..http import proxy_enabled

# Default cap applied to free-text fields controlled by a third party
# (WHOIS, DNS TXT, ASN — Phase 4.3 mitigation, see docs/THREAT_MODEL.md).
# Same value as the cap already used for GitHub snippets (Phase 2.4, after a
# real-world case of a 241,893-character repository description).
THIRD_PARTY_TEXT_CAP = 300


def cap_text(value: Any, max_len: int = THIRD_PARTY_TEXT_CAP) -> Any:
    """Truncate a third-party text string to `max_len` characters.

    Any non-string value (None, lists handled elsewhere, etc.) is passed
    through unchanged.
    """
    if isinstance(value, str) and len(value) > max_len:
        return value[:max_len]
    return value


class Tool:
    """Wraps a callable with the metadata the LLM expects."""

    def __init__(
        self,
        name: str,
        description: str,
        parameters: dict[str, Any],
        func: Callable[..., dict[str, Any]],
        passive: bool = True,
    ) -> None:
        self.name = name
        self.description = description
        self.parameters = parameters
        self._func = func
        # `passive=False` marks a tool that contacts the target DIRECTLY:
        # it is only used in active reconnaissance mode (see tools/__init__).
        self.passive = passive

    def spec(self) -> dict[str, Any]:
        """Schema in the OpenAI/DeepSeek API `tools` format."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def run(self, **kwargs: Any) -> dict[str, Any]:
        """Run the tool, backed by the disk cache or eval fixtures.

        Three modes (see fixtures.py):
          - replay mode: serves only the recorded fixture and fails
            explicitly if it is missing (never falls back to the network);
          - record mode: bypasses cache reads (always a real request) and
            records EVERY result, success or error;
          - normal mode: best-effort disk cache (TTL, silent).

        A valid result is served from the cache if present (avoids repeating
        the external request). Errors are never cached (we want to retry a
        temporarily unavailable source). Exceptions are caught and returned
        as an error dict, so the agent loop can pass them to the model
        without crashing."""
        if fixtures.replaying():
            return fixtures.load(self.name, kwargs)

        is_recording = fixtures.recording()
        # Active tools hit the target directly or via the proxy: never reuse a
        # result collected in the other proxy mode.
        key = cache.make_key(
            self.name, kwargs if self.passive else {**kwargs, "_via_proxy": proxy_enabled()}
        )
        if not is_recording:
            cached = cache.get(key)
            if cached is not None:
                return cached

        try:
            result = self._func(**kwargs)
        except Exception as exc:  # noqa: BLE001 — we want to catch everything here
            result = {"error": f"{type(exc).__name__}: {exc}"}

        if isinstance(result, dict) and "error" not in result:
            cache.set(key, result)
        if is_recording:
            fixtures.save(self.name, kwargs, result)
        return result
