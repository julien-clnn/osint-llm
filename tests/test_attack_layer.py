"""ATT&CK layer end to end, offline: `attack_lookup` tool, agent prompt and
schema with/without the layer, report rendering, verifier ID guard and the
final strip of invented IDs.

The tool runs on the mini corpus with the offline hashing embedder (no
Mistral call); both LLMs are mocked at the provider level.
"""

from __future__ import annotations

import os

os.environ.setdefault("DEEPSEEK_API_KEY", "fake-key-for-tests")

import importlib  # noqa: E402

import pytest  # noqa: E402

from osintllm import fixtures  # noqa: E402
from osintllm.agent import (  # noqa: E402
    OsintAgent,
    build_submit_report_spec,
    build_system_prompt,
)
from osintllm.investigation import Investigator  # noqa: E402
from osintllm.llm import CompletionResult, ToolCallRequest  # noqa: E402
from osintllm.rag.embeddings import HashingEmbedder  # noqa: E402
from osintllm.rag.retriever import AttackRetriever  # noqa: E402
from osintllm.report import OsintReport, attack_url  # noqa: E402
from osintllm.tools import TOOLS_BY_NAME  # noqa: E402
from osintllm.verifier import invented_attack_ids, retrieved_attack_ids  # noqa: E402
from test_rag_retriever import mini_index  # noqa: E402

# The package re-exports the Tool object under the module's name.
tool_module = importlib.import_module("osintllm.tools.attack_lookup_tool")

LOOKUP = {
    "attack_version": "mini",
    "results": [
        {
            "observation": "DMARC p=none",
            "retrieval": "hybrid",
            "techniques": [
                {"attack_id": "T1566", "name": "Phishing", "tactics": ["Initial Access"],
                 "url": "https://attack.mitre.org/techniques/T1566",
                 "excerpt": "missing DMARC policy makes sender spoofing easier", "score": 0.03},
            ],
        }
    ],
}


@pytest.fixture(autouse=True)
def mini_retriever():
    tool_module.set_retriever(AttackRetriever(mini_index(), HashingEmbedder()))
    yield
    tool_module.set_retriever(None)


def _call(name: str, args: dict, call_id: str = "c1") -> CompletionResult:
    return CompletionResult(
        message={"role": "assistant", "content": None, "tool_calls": []},
        content=None,
        tool_calls=[ToolCallRequest(id=call_id, name=name, arguments=args)],
    )


def _scripted(decisions):
    it = iter(decisions)
    return lambda **kwargs: next(it)


# --- tool -------------------------------------------------------------------

def test_attack_lookup_batches_observations():
    result = TOOLS_BY_NAME["attack_lookup"].run(
        observations=["AWS access keys in public source code repositories",
                      "DMARC policy missing, sender spoofing possible"],
        k=2,
    )
    assert result["attack_version"] == "mini"
    assert [r["techniques"][0]["attack_id"] for r in result["results"]] == ["T1552.001", "T1566"]
    assert all(len(r["techniques"]) == 2 for r in result["results"])
    assert result["results"][0]["retrieval"] == "hybrid"


def test_attack_lookup_rejects_empty_input():
    assert "error" in TOOLS_BY_NAME["attack_lookup"].run(observations=["  "])


def test_attack_lookup_bypasses_replay_fixtures(monkeypatch):
    """A free-text query never matches a fixture: the tool always runs."""
    monkeypatch.setenv("OSINTLLM_FIXTURE_MODE", "replay")
    fixtures.set_current_domain("example.com")
    result = TOOLS_BY_NAME["attack_lookup"].run(observations=["phishing e-mail"])
    assert "error" not in result


def test_attack_lookup_falls_back_to_bm25_without_embedder():
    tool_module.set_retriever(AttackRetriever(mini_index(), embedder=None))
    result = TOOLS_BY_NAME["attack_lookup"].run(observations=["phishing e-mail"])
    assert result["results"][0]["retrieval"].startswith("bm25")
    assert result["results"][0]["techniques"]


# --- prompt / schema ----------------------------------------------------------

def test_layer_off_keeps_prompt_and_schema_unchanged():
    assert build_system_prompt("passive") == build_system_prompt("passive", attack_rag=False)
    assert "attack_lookup" not in build_system_prompt("passive")
    props = build_submit_report_spec()["function"]["parameters"]["properties"]
    assert "attack_mappings" not in props


def test_layer_on_adds_rule_and_optional_field():
    assert "attack_lookup" in build_system_prompt("passive", attack_rag=True)
    params = build_submit_report_spec(attack_rag=True)["function"]["parameters"]
    assert "attack_mappings" in params["properties"]
    assert "attack_mappings" not in params["required"]


def _agent(attack_rag: bool) -> OsintAgent:
    agent = OsintAgent()
    agent.settings = type(agent.settings)(
        api_key="fake", base_url=agent.settings.base_url, model=agent.settings.model,
        attack_rag=attack_rag,
    )
    return agent


@pytest.mark.parametrize("attack_rag", [True, False])
def test_tool_exposure_follows_the_setting(attack_rag):
    agent = _agent(attack_rag)
    seen = {}

    def capture(**kwargs):
        seen["tools"] = {t["function"]["name"] for t in kwargs["tools"]}
        return _call("submit_report", {"summary": "s", "risk_level": "low",
                                       "recommendations": []})

    agent.provider.complete = capture
    agent.run("example.com")
    assert ("attack_lookup" in seen["tools"]) is attack_rag


def test_restricted_scenario_never_gets_the_tool():
    from osintllm.scenarios import load_scenario

    tools, rag = _agent(True)._tools_and_rag("passive", load_scenario("email_security_posture"))
    assert rag is False
    assert "attack_lookup" not in {t.name for t in tools}


def test_agent_collects_lookup_and_parses_mappings():
    agent = _agent(True)
    agent.provider.complete = _scripted([
        _call("attack_lookup", {"observations": ["DMARC policy missing, spoofing"]}),
        _call("submit_report", {
            "summary": "1. E-MAIL\n- DMARC: missing", "risk_level": "medium",
            "recommendations": ["Publish DMARC"],
            "attack_mappings": [
                {"finding": "No DMARC", "technique_id": "T1566", "technique_name": "Phishing",
                 "justification": "spoofing easier"},
                {"finding": "malformed"},  # no technique_id: dropped
                "not a dict",
            ],
        }, call_id="c2"),
    ])
    report = agent.run("example.com").report
    assert report.attack_mappings == [{"finding": "No DMARC", "technique_id": "T1566",
                                       "technique_name": "Phishing",
                                       "justification": "spoofing easier"}]
    assert "T1566" in retrieved_attack_ids(report)
    assert invented_attack_ids(report) == []


# --- report -------------------------------------------------------------------

def _report(**kwargs) -> OsintReport:
    fields = {"summary": "Summary", "risk_level": "medium",
              "collected": {"attack_lookup": [{"arguments": {}, "result": LOOKUP}]}}
    return OsintReport(domain="example.com", **{**fields, **kwargs})


def test_attack_url_only_for_wellformed_ids():
    assert attack_url("T1583.001") == "https://attack.mitre.org/techniques/T1583/001"
    assert attack_url("javascript:alert(1)") is None


def test_exports_render_mappings_and_stay_backward_compatible():
    mapping = {"finding": "No DMARC <b>", "technique_id": "T1566",
               "technique_name": "Phishing", "justification": "spoofing | easier"}
    report = _report(attack_mappings=[mapping])
    assert report.to_dict()["attack_mappings"] == [mapping]
    md = report.to_markdown()
    assert "## MITRE ATT&CK mapping" in md
    assert "[T1566](https://attack.mitre.org/techniques/T1566)" in md
    assert "spoofing \\| easier" in md
    html_out = report.to_html()
    assert "MITRE ATT&amp;CK mapping" in html_out
    assert "No DMARC &lt;b&gt;" in html_out
    # Reports without the layer (incl. archived ones) render no section.
    plain = OsintReport(domain="example.com")
    assert plain.to_dict()["attack_mappings"] == []
    assert "ATT&CK" not in plain.to_markdown()


# --- verifier guard + final strip ---------------------------------------------

def test_invented_ids_are_detected_in_mappings_and_free_text():
    report = _report(
        summary="Maps to T1566 and also T1110.003.",
        attack_mappings=[{"finding": "x", "technique_id": "T1078", "technique_name": "",
                          "justification": ""}],
    )
    assert invented_attack_ids(report) == ["T1078", "T1110.003"]


def _verdict(verified: bool) -> CompletionResult:
    return _call("submit_verification", {"verified": verified, "unsupported_claims": [],
                                         "corrections": []})


def test_verifier_flags_invented_id_even_if_llm_says_verified():
    inv = Investigator()
    inv.agent.settings = inv.settings
    inv.agent.provider.complete = _scripted([
        _call("attack_lookup", {"observations": ["DMARC policy missing"]}),
        _call("submit_report", {
            "summary": "Credential stuffing risk (T1110.004).", "risk_level": "medium",
            "recommendations": [],
            "attack_mappings": [{"finding": "f", "technique_id": "T1110.004",
                                 "technique_name": "Credential Stuffing", "justification": "j"}],
        }, call_id="c2"),
        # Correction: the invented ID is gone.
        _call("submit_report", {"summary": "Weak e-mail authentication.",
                                "risk_level": "medium", "recommendations": [],
                                "attack_mappings": []}),
    ])
    inv.verifier.provider.complete = _scripted([_verdict(True), _verdict(True)])

    result = inv.run("example.com")

    first = result.verifications[0]
    assert first.verified is False
    assert first.invented_attack_ids == ["T1110.004"]
    assert result.correction_rounds == 1
    assert result.verified is True
    assert result.stripped_attack_ids == []
    assert invented_attack_ids(result.final_report) == []


def test_invented_id_surviving_the_loop_is_stripped():
    inv = Investigator()
    stubborn = _call("submit_report", {
        "summary": "Related to T1110.004.", "risk_level": "medium", "recommendations": [],
        "attack_mappings": [{"finding": "f", "technique_id": "T1110.004",
                             "technique_name": "Credential Stuffing", "justification": "j"}],
    })
    inv.agent.provider.complete = _scripted([stubborn] * 5)
    inv.verifier.provider.complete = _scripted([_verdict(True)] * 5)

    result = inv.run("example.com")

    assert result.stripped_attack_ids == ["T1110.004"]
    assert result.final_report.attack_mappings == []
    assert "T1110.004" not in result.final_report.summary
    assert "[unverified ATT&CK ID removed]" in result.final_report.summary
    assert result.verified is False


def test_malformed_mapping_id_is_caught_and_stripped():
    """A tactic or malformed ID escapes the free-text pattern but is still
    not a retrieved technique."""
    report = _report(attack_mappings=[
        {"finding": "f", "technique_id": "TA0042", "technique_name": "Resource Development",
         "justification": "j"},
        {"finding": "g", "technique_id": "T1566", "technique_name": "Phishing",
         "justification": "j"},
    ])
    assert invented_attack_ids(report) == ["TA0042"]

    from osintllm.investigation import _strip_invented_attack_ids

    stripped, removed = _strip_invented_attack_ids(report, lambda e: None)
    assert removed == ["TA0042"]
    assert [m["technique_id"] for m in stripped.attack_mappings] == ["T1566"]


def _forced_run(first_tool: str, first_args: dict):
    """2-step budget + 1 ATT&CK step: two tool steps, then the forced report."""
    agent = OsintAgent()
    agent.settings = type(agent.settings)(
        api_key="fake", base_url=agent.settings.base_url, model=agent.settings.model,
        max_iterations=2, attack_rag=True,
    )
    forced_props = {}

    def script(**kwargs):
        if kwargs["tool_choice"] == "auto":
            n = len([m for m in kwargs["messages"] if m["role"] == "tool"])
            name, args = (first_tool, first_args) if n == 0 else (
                "whois_lookup", {"domain": "example.com"})
            return _call(name, args, call_id=f"c{n}")
        forced_props.update(kwargs["tools"][0]["function"]["parameters"]["properties"])
        return _call("submit_report", {
            "summary": "s", "risk_level": "low", "recommendations": [],
            "attack_mappings": [{"finding": "f", "technique_id": "T1566",
                                 "technique_name": "Phishing", "justification": "j"}],
        }, call_id="cf")

    agent.provider.complete = script
    return agent.run("example.com").report, forced_props


def test_forced_report_without_lookup_has_no_mappings(monkeypatch):
    monkeypatch.setattr(TOOLS_BY_NAME["whois_lookup"], "_func",
                        lambda **kwargs: {"domain": "example.com"})
    report, props = _forced_run("whois_lookup", {"domain": "example.com"})
    assert report.stopped_reason == "report_forced"
    assert "attack_mappings" not in props
    assert report.attack_mappings == []


def test_forced_report_after_lookup_keeps_mappings(monkeypatch):
    monkeypatch.setattr(TOOLS_BY_NAME["whois_lookup"], "_func",
                        lambda **kwargs: {"domain": "example.com"})
    report, props = _forced_run("attack_lookup", {"observations": ["DMARC policy missing"]})
    assert report.stopped_reason == "report_forced"
    assert "attack_mappings" in props
    assert [m["technique_id"] for m in report.attack_mappings] == ["T1566"]


@pytest.mark.parametrize("with_lookup", [False, True])
def test_revision_offers_mappings_only_after_a_lookup(with_lookup):
    agent = _agent(True)
    collected = {"attack_lookup": [{"arguments": {}, "result": LOOKUP}]} if with_lookup else {}
    seen = {}

    def revise(**kwargs):
        seen["props"] = kwargs["tools"][0]["function"]["parameters"]["properties"]
        seen["prompt"] = kwargs["messages"][0]["content"]
        return _call("submit_report", {
            "summary": "s", "risk_level": "low", "recommendations": [],
            "attack_mappings": [{"finding": "f", "technique_id": "T1566",
                                 "technique_name": "Phishing", "justification": "j"}],
        })

    agent.provider.complete = revise
    revised = agent.revise_report(
        OsintReport(domain="example.com", collected=collected), ["fix it"]
    )
    assert ("attack_mappings" in seen["props"]) is with_lookup
    assert ("attack_lookup" in seen["prompt"]) is with_lookup
    assert bool(revised.attack_mappings) is with_lookup
