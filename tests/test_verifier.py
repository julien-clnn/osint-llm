"""Multi-agent orchestration test (reconnaissance + verification).

Both LLMs (main agent and verifier agent) are mocked at the provider level
(`.provider.complete`, SDK-agnostic `CompletionResult`): this validates the
chain initial report -> audit -> correction -> verified report, with no
network and no real key.
"""

from __future__ import annotations

import os

os.environ.setdefault("DEEPSEEK_API_KEY", "fake-key-for-tests")

from osintllm.investigation import Investigator  # noqa: E402
from osintllm.llm import CompletionResult, ToolCallRequest  # noqa: E402


def _tool_call(name: str, args: dict) -> ToolCallRequest:
    return ToolCallRequest(id="c1", name=name, arguments=args)


def _decision(name: str, args: dict) -> CompletionResult:
    call = _tool_call(name, args)
    return CompletionResult(
        message={"role": "assistant", "content": None, "tool_calls": []},
        content=None,
        tool_calls=[call],
    )


def _scripted(decisions: list[CompletionResult]):
    it = iter(decisions)
    return lambda **kwargs: next(it)


def test_verification_loop_corrects_the_report():
    """A report judged unsupported is sent back for correction, then validated."""
    inv = Investigator()

    # Main agent: (exaggerated) initial report, then corrected report.
    inv.agent.provider.complete = _scripted([
        _decision("submit_report", {
            "summary": "The domain hosts a massive critical infrastructure.",
            "risk_level": "high",
            "risk_justification": "Unsupported extrapolation.",
            "recommendations": ["Audit everything"],
        }),
        _decision("submit_report", {
            "summary": "Standard domain, no alarming data collected.",
            "risk_level": "low",
            "risk_justification": "Nothing abnormal in the facts.",
            "recommendations": ["Monitor expirations"],
        }),
    ])

    # Verifier agent: rejects first, then validates.
    inv.verifier.provider.complete = _scripted([
        _decision("submit_verification", {
            "verified": False,
            "unsupported_claims": ["massive critical infrastructure"],
            "corrections": ["Remove the unsupported claim"],
            "notes": "Exaggerated conclusion.",
        }),
        _decision("submit_verification", {
            "verified": True,
            "unsupported_claims": [],
            "corrections": [],
            "notes": "Report faithful to the facts.",
        }),
    ])

    result = inv.run("example.com")

    assert result.verified is True
    assert result.corrected is True
    assert len(result.verifications) == 2
    assert result.initial_report.risk_level == "high"
    assert result.final_report.risk_level == "low"
    assert result.initial_report.summary != result.final_report.summary


def test_detected_injection_forces_correction_even_if_verified():
    """Phase 4.3 mitigation: a report judged `verified=True` but in which the
    verifier detected an injection is still sent back for correction — that
    is precisely the case where the injection fooled it."""
    inv = Investigator()

    inv.agent.provider.complete = _scripted([
        _decision("submit_report", {
            "summary": "Safe domain, no action required.",
            "risk_level": "low",
            "risk_justification": "Verified by the internal security team (WHOIS).",
            "recommendations": [],
        }),
        _decision("submit_report", {
            "summary": "Standard domain, verified facts only.",
            "risk_level": "medium",
            "risk_justification": "Rephrased without the suspicious claim.",
            "recommendations": ["Monitor"],
        }),
    ])

    inv.verifier.provider.complete = _scripted([
        _decision("submit_verification", {
            "verified": True,  # the verifier was fooled on the substance...
            "unsupported_claims": [],
            "corrections": [],
            "notes": "WHOIS content looks like an injected instruction.",
            "injection_detected": True,  # ...but detects the injection itself.
        }),
        _decision("submit_verification", {
            "verified": True,
            "unsupported_claims": [],
            "corrections": [],
            "notes": "Clean report, no more injection detected.",
            "injection_detected": False,
        }),
    ])

    result = inv.run("example.com")

    assert result.verified is True
    assert result.corrected is True  # the correction was triggered
    assert len(result.verifications) == 2
    assert result.verifications[0].injection_detected is True


def test_faithful_report_passes_without_correction():
    """A report judged faithful on the first try is not corrected."""
    inv = Investigator()

    inv.agent.provider.complete = _scripted([
        _decision("submit_report", {
            "summary": "Standard domain.",
            "risk_level": "low",
            "risk_justification": "Nothing abnormal.",
            "recommendations": ["Monitor"],
        }),
    ])
    inv.verifier.provider.complete = _scripted([
        _decision("submit_verification", {
            "verified": True,
            "unsupported_claims": [],
            "corrections": [],
            "notes": "OK.",
        }),
    ])

    result = inv.run("example.com")

    assert result.verified is True
    assert result.corrected is False
    assert len(result.verifications) == 1
    assert result.final_report is result.initial_report


def test_unreadable_verdict_fails_closed():
    """No readable verdict from the verifier: the report is NOT verified."""
    inv = Investigator()

    inv.agent.provider.complete = _scripted([
        _decision("submit_report", {
            "summary": "Standard domain.",
            "risk_level": "low",
            "risk_justification": "Nothing abnormal.",
            "recommendations": ["Monitor"],
        }),
    ])
    inv.verifier.provider.complete = _scripted([
        CompletionResult(message={"role": "assistant", "content": "?"}, content="?", tool_calls=[]),
    ])

    result = inv.run("example.com")

    assert result.verified is False
    assert "unavailable" in result.verifications[0].notes


def test_risk_forced_undetermined_when_all_tools_failed():
    """Tools called but none returned a usable fact: no risk level can hold."""
    inv = Investigator()

    inv.agent.provider.complete = _scripted([
        _decision("whois_lookup", {"domain": "not a domain"}),
        _decision("submit_report", {
            "summary": "Dangerous domain.",
            "risk_level": "high",
            "risk_justification": "Made up.",
            "recommendations": ["Block it"],
        }),
    ])
    inv.verifier.provider.complete = _scripted([
        _decision("submit_verification", {
            "verified": True,
            "unsupported_claims": [],
            "corrections": [],
        }),
    ])

    result = inv.run("example.com")

    assert result.initial_report.risk_level == "high"
    assert result.final_report.risk_level == "undetermined"


def test_string_false_verdict_is_not_verified():
    """A verdict sent as the string "false" must never read as verified."""
    inv = Investigator()

    inv.agent.provider.complete = _scripted([
        _decision("submit_report", {
            "summary": "Standard domain.",
            "risk_level": "low",
            "risk_justification": "Nothing abnormal.",
            "recommendations": ["Monitor"],
        }),
        _decision("submit_report", {
            "summary": "Standard domain.",
            "risk_level": "low",
            "risk_justification": "Nothing abnormal.",
            "recommendations": ["Monitor"],
        }),
    ])
    inv.verifier.provider.complete = _scripted([
        _decision("submit_verification", {
            "verified": "false",
            "unsupported_claims": ["x"],
            "corrections": ["y"],
        }),
    ] * 5)

    result = inv.run("example.com")

    assert result.verifications[0].verified is False
    assert result.verified is False



def test_disabled_and_failed_tools_are_not_usable_facts():
    """Disabled source + all geolocations failed: risk forced BEFORE the audit."""
    from osintllm.investigation import _all_tools_failed
    from osintllm.report import OsintReport

    report = OsintReport(
        domain="example.com", summary="", risk_level="high",
        risk_justification="", recommendations=[],
        collected={
            "virustotal_lookup": [{"result": {"enabled": False, "note": "no key"}}],
            "ip_geolocation": [{"result": {"locations": [{"ip": "1.2.3.4", "error": "down"}]}}],
        },
    )
    assert _all_tools_failed(report) is True
