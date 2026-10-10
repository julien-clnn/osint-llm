"""Agent loop tests, without a real API key.

LLM responses are mocked at the provider level (`agent.provider.complete`,
which returns an SDK-agnostic `CompletionResult`); the collection tools run
for real. This validates the orchestration: tool call -> fact archived ->
`submit_report` intercepted -> structured report built.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("DEEPSEEK_API_KEY", "fake-key-for-tests")

from osintllm.agent import OsintAgent  # noqa: E402  (after the setenv)
from osintllm.llm import CompletionResult, ToolCallRequest  # noqa: E402


def _tool_call(cid: str, name: str, args: dict) -> ToolCallRequest:
    return ToolCallRequest(id=cid, name=name, arguments=args)


def _decision(
    tool_calls: list[ToolCallRequest] | None = None, content: str | None = None
) -> CompletionResult:
    return CompletionResult(
        message={"role": "assistant", "content": content, "tool_calls": []},
        content=content,
        tool_calls=tool_calls or [],
    )


def _agent_with_script(script: list[CompletionResult]) -> OsintAgent:
    """Build an agent whose provider returns the decisions of `script`."""
    agent = OsintAgent()
    calls = iter(script)
    agent.provider.complete = lambda **kwargs: next(calls)
    return agent


def test_multi_tool_then_submit_report():
    """The loop collects a fact, then ends on submit_report."""
    script = [
        _decision(tool_calls=[
            _tool_call("c1", "whois_lookup", {"domain": "example.com"})
        ]),
        _decision(tool_calls=[
            _tool_call("c2", "submit_report", {
                "summary": "Reserved domain, stable infrastructure.",
                "risk_level": "low",
                "risk_justification": "No abnormal exposure.",
                "recommendations": ["Monitor the expiration date."],
            })
        ]),
    ]
    result = _agent_with_script(script).run("example.com")
    rep = result.report

    assert rep.stopped_reason == "report_submitted"
    assert rep.risk_level == "low"
    assert rep.recommendations == ["Monitor the expiration date."]
    # The whois fact was archived (real tool result).
    assert "whois_lookup" in rep.collected
    assert "result" in rep.collected["whois_lookup"][0]


def test_invalid_risk_level_is_normalized():
    """An out-of-enum risk value falls back cleanly."""
    script = [
        _decision(tool_calls=[
            _tool_call("c1", "submit_report", {
                "summary": "x",
                "risk_level": "CRITICAL",  # out of enum
                "recommendations": [],
            })
        ]),
    ]
    rep = _agent_with_script(script).run("example.com").report
    assert rep.risk_level == "undetermined"


def test_legacy_french_risk_level_is_mapped_to_english():
    """A legacy French risk value (pre-migration) maps to its English level."""
    script = [
        _decision(tool_calls=[
            _tool_call("c1", "submit_report", {
                "summary": "x",
                "risk_level": "Élevé",
                "recommendations": [],
            })
        ]),
    ]
    rep = _agent_with_script(script).run("example.com").report
    assert rep.risk_level == "high"


def test_free_text_produces_degraded_report():
    """If the model answers in text without submit_report, not everything is lost."""
    script = [
        _decision(tool_calls=None, content="Here is my free-form analysis."),
    ]
    rep = _agent_with_script(script).run("example.com").report
    assert rep.stopped_reason == "free_text"
    assert rep.summary == "Here is my free-form analysis."
    assert rep.risk_level == "undetermined"


def test_max_iterations_guardrail():
    """Without ever submitting a report, the loop stops at max_iterations."""
    # The model always calls a tool again -> never a natural end.
    def always_tool(**kwargs):
        return _decision(tool_calls=[
            _tool_call("cx", "whois_lookup", {"domain": "example.com"})
        ])

    agent = OsintAgent()
    agent.settings = type(agent.settings)(
        api_key="fake", base_url=agent.settings.base_url,
        model=agent.settings.model, max_iterations=2,
    )
    agent.provider.complete = always_tool
    rep = agent.run("example.com").report
    assert rep.stopped_reason == "max_iterations"
    assert rep.iterations == 2


def test_tool_results_delimited_as_data():
    """Injection mitigation (Phase 4.3): the `role: tool` message sent to the
    LLM explicitly delimits the result as DATA, never an instruction — even
    if the result contains text that looks like one."""
    script = [
        _decision(tool_calls=[
            _tool_call("c1", "whois_lookup", {"domain": "example.com"})
        ]),
        _decision(tool_calls=[
            _tool_call("c2", "submit_report", {
                "summary": "x", "risk_level": "low", "recommendations": [],
            })
        ]),
    ]
    captured_messages: list[list[dict]] = []
    calls = iter(script)

    def capturing_complete(**kwargs):
        captured_messages.append(kwargs["messages"])
        return next(calls)

    agent = OsintAgent()
    agent.provider.complete = capturing_complete
    agent.run("example.com")

    # The 2nd LLM call contains the tool message with the whois result.
    tool_message = next(m for m in captured_messages[1] if m.get("role") == "tool")
    assert tool_message["content"].startswith("[RAW DATA")
    assert tool_message["content"].rstrip().endswith("[END RAW DATA]")
    assert "never" in tool_message["content"]


def test_off_target_tech_fingerprint_refused_without_http_request():
    """Exfiltration mitigation (Phase 4.3): a `tech_fingerprint` call whose
    domain is neither the investigated target nor one of its subdomains is
    refused before any network request (allow-list)."""
    script = [
        _decision(tool_calls=[
            _tool_call("c1", "tech_fingerprint", {"domain": "attacker-collector.example"})
        ]),
        _decision(tool_calls=[
            _tool_call("c2", "submit_report", {
                "summary": "x", "risk_level": "low", "recommendations": [],
            })
        ]),
    ]
    rep = _agent_with_script(script).run("example.com", mode="active").report

    result = rep.collected["tech_fingerprint"][0]["result"]
    assert "error" in result
    assert "allow-list" in result["error"]


def test_domain_in_scope_covers_domain_and_subdomains():
    """Unit test of the allow-list rule itself: the target and its
    subdomains pass, everything else is refused."""
    from osintllm.agent import _domain_in_scope

    assert _domain_in_scope("example.com", "example.com")
    assert _domain_in_scope("www.example.com", "example.com")
    assert _domain_in_scope("EXAMPLE.COM", "example.com")  # case-insensitive
    assert not _domain_in_scope("attacker-collector.example", "example.com")
    assert not _domain_in_scope("notexample.com", "example.com")  # not a real subdomain
    assert not _domain_in_scope("", "example.com")


def test_run_without_scenario_behaves_like_default_scenario():
    """Phase 3 non-regression: omitting `scenario` must produce exactly the
    same behavior as before scenarios were introduced."""
    from osintllm.scenarios import load_scenario

    script = [
        _decision(tool_calls=[
            _tool_call("c1", "submit_report", {
                "summary": "x",
                "risk_level": "low",
                "recommendations": [],
            })
        ]),
    ]
    rep_without = _agent_with_script(script).run("example.com").report
    rep_with = _agent_with_script(list(script)).run(
        "example.com", scenario=load_scenario("external_recon")
    ).report
    assert rep_without.risk_level == rep_with.risk_level == "low"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
