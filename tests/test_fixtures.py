"""Tests for the --record/--replay fixtures mode (see fixtures.py, tools/base.py).

Checks the separation from the best-effort cache (cache.py): replay mode
serves ONLY fixtures and fails explicitly when they are missing; record mode
saves every result, errors included, without ever silently falling back to
the network.
"""

from __future__ import annotations

import pytest

from osintllm import fixtures
from osintllm.tools.base import Tool


@pytest.fixture(autouse=True)
def _isolated_fixtures(tmp_path, monkeypatch):
    """Redirect fixtures to a temporary directory, mode disabled by default."""
    monkeypatch.setenv("OSINTLLM_FIXTURES_DIR", str(tmp_path))
    monkeypatch.delenv("OSINTLLM_FIXTURE_MODE", raising=False)
    # OSINTLLM_FIXTURES_DIR is read only once at module load time, so the
    # constant is patched directly to isolate each test.
    monkeypatch.setattr(fixtures, "FIXTURES_ROOT", tmp_path)


def _counting_tool(calls: list[int]) -> Tool:
    def _func(domain: str) -> dict:
        calls.append(1)
        return {"domain": domain, "found": True}

    return Tool(
        name="whois_lookup",
        description="test",
        parameters={"type": "object", "properties": {}},
        func=_func,
    )


def test_replay_without_fixture_raises_explicit_error(monkeypatch):
    monkeypatch.setenv("OSINTLLM_FIXTURE_MODE", "replay")
    fixtures.set_current_domain("example.com")
    tool = _counting_tool([])

    with pytest.raises(fixtures.FixtureMissError):
        tool.run(domain="example.com")


def test_record_then_replay_returns_same_result(monkeypatch):
    fixtures.set_current_domain("example.com")
    calls: list[int] = []
    tool = _counting_tool(calls)

    monkeypatch.setenv("OSINTLLM_FIXTURE_MODE", "record")
    recorded = tool.run(domain="example.com")
    assert calls == [1]  # real request executed

    monkeypatch.setenv("OSINTLLM_FIXTURE_MODE", "replay")
    replayed = tool.run(domain="example.com")
    assert replayed == recorded
    assert calls == [1]  # no new execution in replay mode


def test_record_bypasses_cache_reads(monkeypatch):
    """In record mode, the tool is always re-run, even if a cache entry exists."""
    fixtures.set_current_domain("example.com")
    calls: list[int] = []
    tool = _counting_tool(calls)

    # First normal call: populates the cache.
    tool.run(domain="example.com")
    assert calls == [1]

    monkeypatch.setenv("OSINTLLM_FIXTURE_MODE", "record")
    tool.run(domain="example.com")
    assert calls == [1, 1]  # executed again, not served from the cache


def test_record_also_saves_errors(monkeypatch):
    fixtures.set_current_domain("example.com")

    def _boom(domain: str) -> dict:
        raise RuntimeError("network outage")

    tool = Tool(
        name="whois_lookup",
        description="test",
        parameters={"type": "object", "properties": {}},
        func=_boom,
    )

    monkeypatch.setenv("OSINTLLM_FIXTURE_MODE", "record")
    result = tool.run(domain="example.com")
    assert "error" in result

    monkeypatch.setenv("OSINTLLM_FIXTURE_MODE", "replay")
    replayed = tool.run(domain="example.com")
    assert replayed == result


def test_normalize_hook_applies_to_live_cached_and_replayed_results(monkeypatch):
    """The hook reshapes every successful result, whatever its origin."""
    fixtures.set_current_domain("example.com")
    tool = Tool(
        name="whois_lookup",
        description="test",
        parameters={"type": "object", "properties": {}},
        func=lambda domain: {"domain": domain, "n": 1},
        normalize=lambda r: {**r, "n": str(r["n"])},
    )

    monkeypatch.setenv("OSINTLLM_FIXTURE_MODE", "record")
    assert tool.run(domain="example.com")["n"] == "1"

    monkeypatch.setenv("OSINTLLM_FIXTURE_MODE", "replay")
    assert tool.run(domain="example.com")["n"] == "1"


def test_normalize_hook_skips_errors(monkeypatch):
    fixtures.set_current_domain("example.com")

    def _boom(domain: str) -> dict:
        raise RuntimeError("network outage")

    tool = Tool(
        name="whois_lookup",
        description="test",
        parameters={"type": "object", "properties": {}},
        func=_boom,
        normalize=lambda r: {"normalized": True},
    )

    assert "error" in tool.run(domain="example.com")
