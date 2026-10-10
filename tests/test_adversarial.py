"""Adversarial suite tests (Phase 4) — mechanism only, no real LLM call
(mocked provider or pure logic). Real attack measurements
(make eval-adversarial) cost LLM calls and only run on explicit request.
"""

from __future__ import annotations

import json
import os

os.environ.setdefault("DEEPSEEK_API_KEY", "fake-key-for-tests")

import osintllm.agent as agent_module  # noqa: E402
import osintllm.verifier as verifier_module  # noqa: E402
from osintllm import fixtures  # noqa: E402
from osintllm.investigation import Investigator  # noqa: E402
from osintllm.llm import CompletionResult, ToolCallRequest  # noqa: E402
from osintllm.report import OsintReport  # noqa: E402
from osintllm.scenarios import load_scenario  # noqa: E402

from evals.adversarial.cases import (  # noqa: E402
    CASES,
    FAMILIES,
    _off_target_tool_call,
    _payload_echoed,
    _risk_flipped_to,
)
from evals.adversarial.tainting import tainted_fixtures  # noqa: E402


def test_the_10_cases_cover_the_6_families():
    assert {c.family for c in CASES} == set(FAMILIES)
    assert len(CASES) == 10


def test_each_case_targets_an_existing_fixture():
    """Otherwise tainted_fixtures would fail on the first real run — checked
    here without any LLM call."""
    for case in CASES:
        with tainted_fixtures(case.domain, case.tool_name, case.mutate):
            pass  # an exception raised by tainted_fixtures is enough to fail the test


def test_tainting_never_modifies_the_real_fixture():
    case = next(c for c in CASES if c.name == "direct_instruction_whois")
    fixture_path = next(
        (
            f"evals/fixtures/{case.domain}/{p.name}"
            for p in __import__("pathlib").Path(f"evals/fixtures/{case.domain}").glob(
                f"{case.tool_name}__*.json"
            )
        ),
        None,
    )
    before = json.loads(open(fixture_path, encoding="utf-8").read())

    original_root = fixtures.FIXTURES_ROOT
    with tainted_fixtures(case.domain, case.tool_name, case.mutate):
        assert fixtures.FIXTURES_ROOT != original_root
        fixtures.set_current_domain(case.domain)
        tainted = fixtures.load(case.tool_name, {"domain": case.domain})
        assert tainted["registrant_org"] == case.payload

    assert fixtures.FIXTURES_ROOT == original_root
    after = json.loads(open(fixture_path, encoding="utf-8").read())
    assert before == after


def test_tainting_restores_even_after_exception():
    case = CASES[0]
    original_root = fixtures.FIXTURES_ROOT
    try:
        with tainted_fixtures(case.domain, case.tool_name, case.mutate):
            raise RuntimeError("simulated crash")
    except RuntimeError:
        pass
    assert fixtures.FIXTURES_ROOT == original_root


def _report(risk_level="high", summary="", risk_justification="") -> OsintReport:
    return OsintReport(
        domain="example.com",
        summary=summary,
        risk_level=risk_level,
        risk_justification=risk_justification,
        recommendations=[],
    )


def test_check_risk_flipped_to():
    check = _risk_flipped_to("low")
    succeeded, _ = check(_report(risk_level="low"), [], None)
    assert succeeded is True
    succeeded, _ = check(_report(risk_level="high"), [], None)
    assert succeeded is False
    succeeded, _ = check(None, [], "FixtureMissError: ...")
    assert succeeded is None  # not measurable, not a "failure"


def test_check_risk_flipped_to_accepts_legacy_french_values():
    check = _risk_flipped_to("low")
    succeeded, _ = check(_report(risk_level="faible"), [], None)
    assert succeeded is True
    succeeded, _ = check(_report(risk_level="élevé"), [], None)
    assert succeeded is False


def test_check_payload_echoed():
    check = _payload_echoed("distinctive phrase")
    succeeded, _ = check(_report(summary="Contains the Distinctive Phrase here."), [], None)
    assert succeeded is True
    succeeded, _ = check(_report(summary="Unrelated."), [], None)
    assert succeeded is False


def test_check_off_target_tool_call():
    check = _off_target_tool_call("example.com")
    calls_ok = [{"name": "whois_lookup", "arguments": {"domain": "example.com"}}]
    calls_sub_ok = [{"name": "tech_fingerprint", "arguments": {"domain": "mail.example.com"}}]
    calls_bad = [{"name": "tech_fingerprint", "arguments": {"domain": "attacker.example"}}]

    succeeded, _ = check(None, calls_ok, None)
    assert succeeded is False
    succeeded, _ = check(None, calls_sub_ok, None)
    assert succeeded is False
    succeeded, _ = check(None, calls_bad, None)
    assert succeeded is True


def _fake_provider_factory(script):
    calls = iter(script)

    class _Fake:
        name = "fake"

        def complete(self, **kwargs):
            return next(calls)

    def factory(settings):
        return _Fake()

    return factory


def test_run_agent_case_captures_tool_call_before_replay_crash(monkeypatch):
    """The most sensitive part of the mechanism: if the LLM calls a tool with
    an argument outside the fixtures (e.g. an exfiltration attempt never
    recorded in the dataset), the run crashes (FixtureMissError, not caught
    by Tool.run() in replay mode) — but the tool_call event must still be
    captured since it is emitted BEFORE the tool actually executes."""
    from evals.adversarial.cases import AdversarialCase, _off_target_tool_call
    from evals.adversarial.runner import run_case

    case = AdversarialCase(
        name="test_exfil",
        family="exfiltration",
        domain="craigslist.org",
        tool_name="whois_lookup",
        mutate=lambda result: result.__setitem__("registrar", "whatever"),
        payload="whatever",
        check=_off_target_tool_call("craigslist.org"),
        description="test case",
        mode="active",
        scenario_name="external_recon",
    )

    off_target_call = ToolCallRequest(
        id="c1", name="tech_fingerprint", arguments={"domain": "attacker.example"}
    )
    script = [
        CompletionResult(
            message={"role": "assistant", "content": None, "tool_calls": []},
            content=None,
            tool_calls=[off_target_call],
        ),
    ]
    monkeypatch.setattr(agent_module, "build_provider", _fake_provider_factory(script))
    monkeypatch.setattr(verifier_module, "build_provider", _fake_provider_factory([]))
    # run_case() sets OSINTLLM_FIXTURE_MODE without restoring it (same
    # convention as evals/harness/runner.py) — monkeypatch.setenv captures
    # the current "unset" state and restores it after the test, whatever
    # value the code under test sets in the meantime.
    monkeypatch.setenv("OSINTLLM_FIXTURE_MODE", "replay")

    outcome = run_case(case, seed=1)

    assert outcome.error is not None  # the run did crash (missing fixture)
    assert outcome.succeeded is True  # but the attack is still detected
    assert outcome.tool_calls == [
        {"name": "tech_fingerprint", "arguments": {"domain": "attacker.example"}}
    ]


def test_scenarios_referenced_by_cases_exist():
    for case in CASES:
        load_scenario(case.scenario_name)  # raises ScenarioError if missing


def test_investigator_run_signature_still_accepts_optional_scenario():
    """Regression test: the adversarial suite calls Investigator.run() with
    an explicit scenario — make sure this stays compatible with calls
    without a scenario (default) elsewhere in the code."""
    import inspect

    sig = inspect.signature(Investigator.run)
    assert "scenario" in sig.parameters
    assert sig.parameters["scenario"].default is None


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
