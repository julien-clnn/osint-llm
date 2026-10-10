"""Tests for the tool-level disk cache."""

from __future__ import annotations

from osintllm.tools.base import Tool


def _counting_tool(func) -> Tool:
    return Tool(name="fake", description="d", parameters={"type": "object"}, func=func)


def test_second_call_served_from_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("OSINTLLM_NO_CACHE", "0")
    monkeypatch.setenv("OSINTLLM_CACHE_DIR", str(tmp_path))

    calls = {"n": 0}

    def func(**kwargs):
        calls["n"] += 1
        return {"ok": True, "args": kwargs}

    tool = _counting_tool(func)
    r1 = tool.run(x=1)
    r2 = tool.run(x=1)

    assert calls["n"] == 1  # the second call does not re-run the function
    assert r1 == r2

    # Different arguments = new execution.
    tool.run(x=2)
    assert calls["n"] == 2


def test_errors_are_not_cached(tmp_path, monkeypatch):
    monkeypatch.setenv("OSINTLLM_NO_CACHE", "0")
    monkeypatch.setenv("OSINTLLM_CACHE_DIR", str(tmp_path))

    calls = {"n": 0}

    def failing(**kwargs):
        calls["n"] += 1
        return {"error": "service unavailable"}

    tool = _counting_tool(failing)
    tool.run()
    tool.run()

    assert calls["n"] == 2  # an error is retried, not served from the cache


def test_disabled_cache_stores_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("OSINTLLM_NO_CACHE", "1")
    monkeypatch.setenv("OSINTLLM_CACHE_DIR", str(tmp_path))

    calls = {"n": 0}

    def func(**kwargs):
        calls["n"] += 1
        return {"ok": True}

    tool = _counting_tool(func)
    tool.run(x=1)
    tool.run(x=1)

    assert calls["n"] == 2  # cache off -> every call re-runs
    assert not list(tmp_path.glob("*.json"))
