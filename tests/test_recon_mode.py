"""Reconnaissance mode tests (passive / active).

The mode determines which tools are exposed to the LLM: in passive mode, no
tool contacts the target directly; in active mode, `tech_fingerprint` (a
light HTTP request) becomes available.
"""

from __future__ import annotations

import os

os.environ.setdefault("DEEPSEEK_API_KEY", "fake-key-for-tests")

from osintllm.agent import build_system_prompt  # noqa: E402
from osintllm import http  # noqa: E402
from osintllm.http import (  # noqa: E402
    DEFAULT_PROXY_URL,
    USER_AGENT,
    _BROWSER_USER_AGENTS,
    _proxies,
    proxy_enabled,
    random_browser_user_agent,
)
from osintllm.tools import (  # noqa: E402
    ALL_TOOLS,
    DEFAULT_MODE,
    tool_specs,
    tools_for_mode,
)


def test_default_is_passive():
    assert DEFAULT_MODE == "passive"


def test_passive_excludes_active_tools():
    """In passive mode, no tool contacts the target (e.g. tech_fingerprint)."""
    names = {t.name for t in tools_for_mode("passive")}
    assert "tech_fingerprint" not in names
    # Every selected tool is indeed passive.
    assert all(t.passive for t in tools_for_mode("passive"))


def test_active_includes_all_tools():
    """In active mode, every tool is available, including active ones."""
    active_tools = tools_for_mode("active")
    assert active_tools == ALL_TOOLS
    assert "tech_fingerprint" in {t.name for t in active_tools}


def test_unknown_mode_falls_back_to_passive():
    """An unexpected mode value is treated as passive (cautious)."""
    assert tools_for_mode("whatever") == tools_for_mode("passive")


def test_specs_reflect_mode():
    passive_names = {s["function"]["name"] for s in tool_specs("passive")}
    active_names = {s["function"]["name"] for s in tool_specs("active")}
    assert "tech_fingerprint" not in passive_names
    assert "tech_fingerprint" in active_names


def test_prompt_frames_the_mode():
    """The system prompt states the right mode and the matching contact rule."""
    passive = build_system_prompt("passive")
    active = build_system_prompt("active")
    assert "PASSIVE" in passive and "NEVER" in passive
    assert "ACTIVE" in active and "tech_fingerprint" in active
    # In passive mode, the model is not pushed toward an unavailable tool.
    assert "tech_fingerprint" not in passive


def test_browser_ua_does_not_sign_osintllm():
    """The random active-mode UA never gives the tool away."""
    for _ in range(50):
        ua = random_browser_user_agent()
        assert ua in _BROWSER_USER_AGENTS
        assert "osintllm" not in ua.lower()
        assert ua != USER_AGENT
        assert ua.startswith("Mozilla/5.0")


def test_browser_ua_varies():
    """Over several draws, more than one UA comes out (randomization)."""
    draws = {random_browser_user_agent() for _ in range(50)}
    assert len(draws) > 1


def test_proxy_disabled_by_default(monkeypatch):
    """Without OSINTLLM_USE_PROXY, no request is routed through a proxy."""
    monkeypatch.delenv("OSINTLLM_USE_PROXY", raising=False)
    assert proxy_enabled() is False
    assert _proxies() is None


def test_proxy_enabled_returns_dict(monkeypatch):
    """When enabled, both http AND https are routed to the proxy URL (Tor by default)."""
    monkeypatch.setenv("OSINTLLM_USE_PROXY", "1")
    monkeypatch.delenv("OSINTLLM_PROXY_URL", raising=False)
    assert proxy_enabled() is True
    assert _proxies() == {"http": DEFAULT_PROXY_URL, "https": DEFAULT_PROXY_URL}


def test_proxy_url_override(monkeypatch):
    """OSINTLLM_PROXY_URL overrides the default URL."""
    monkeypatch.setenv("OSINTLLM_USE_PROXY", "1")
    monkeypatch.setenv("OSINTLLM_PROXY_URL", "socks5h://127.0.0.1:9150")
    assert _proxies() == {
        "http": "socks5h://127.0.0.1:9150",
        "https": "socks5h://127.0.0.1:9150",
    }


def test_get_response_passes_proxies(monkeypatch):
    """get_response forwards the proxies dict to requests when enabled."""
    monkeypatch.setenv("OSINTLLM_USE_PROXY", "1")
    monkeypatch.delenv("OSINTLLM_PROXY_URL", raising=False)
    captured = {}

    def fake_get(url, **kwargs):
        captured.update(kwargs)
        return "response"

    monkeypatch.setattr(http._session, "get", fake_get)
    monkeypatch.setattr(http, "_throttle", lambda host: None)
    http.get_response("https://example.com/", host="example.com")
    assert captured["proxies"] == {
        "http": DEFAULT_PROXY_URL,
        "https": DEFAULT_PROXY_URL,
    }


def test_get_response_without_proxy_passes_nothing(monkeypatch):
    """Without a proxy, no proxies key is forced (direct behavior)."""
    monkeypatch.delenv("OSINTLLM_USE_PROXY", raising=False)
    captured = {}
    monkeypatch.setattr(
        http._session, "get", lambda url, **kwargs: captured.update(kwargs)
    )
    monkeypatch.setattr(http, "_throttle", lambda host: None)
    http.get_response("https://example.com/", host="example.com")
    assert "proxies" not in captured


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
