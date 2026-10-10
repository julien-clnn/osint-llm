"""Projection of an `AgentEvent` into the (event_name, payload) shape expected
by the frontend — shared between `api.py` (SSE stream of `/api/analyze`) and
`evals/harness/cli.py` (benchmark event stream, emitted as JSON on stdout
behind `AGENT_EVENT_STDOUT_PREFIX` so `/api/eval/launch` can tell them apart
from regular log lines).
"""

from __future__ import annotations

import json
from typing import Any

from .agent import AgentEvent

# Prefix that distinguishes, in the stdout of the `run_eval.py` subprocess,
# an agent event line (JSON) from an ordinary human-readable log line.
AGENT_EVENT_STDOUT_PREFIX = "@@EVENT@@ "


def project_agent_event(event: AgentEvent) -> tuple[str, dict[str, Any]] | None:
    """Reduce an AgentEvent to what the frontend needs (live log).

    Ignores the `final` event: each caller already closes the stream its own
    way (the `/api/analyze` worker via the `report` event, the benchmark
    harness via its own end-of-task marker).
    """
    d = event.data
    if event.type == "info":
        return "info", {"message": d.get("message", "")}
    if event.type == "assistant_message":
        return "assistant_message", {"content": d.get("content", "")}
    if event.type == "tool_call":
        args = d.get("arguments", {})
        return "tool_call", {
            "name": d.get("name", ""),
            "arguments": json.dumps(args, ensure_ascii=False) if args else "",
        }
    if event.type == "tool_result":
        result = d.get("result", {}) or {}
        return "tool_result", {
            "name": d.get("name", ""),
            "ok": "error" not in result,
            "error": result.get("error", ""),
        }
    if event.type == "verification":
        return "verification", {
            "iteration": d.get("iteration", 1),
            "verified": d.get("verified", True),
            "unsupported_claims": d.get("unsupported_claims", []),
            "corrections": d.get("corrections", []),
            "notes": d.get("notes", ""),
        }
    return None
