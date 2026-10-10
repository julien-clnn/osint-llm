"""Execute a full run (with or without the verifier agent) against a domain,
in --replay mode (no network on the tools side), and capture everything the
metrics need: report(s), events, token usage and latency per LLM call.

Usage/latency is captured by wrapping `provider.complete` in an
instrumentation shim rather than modifying agent.py/verifier.py — this
directly leverages the provider/orchestration split made in Phase 1,
without touching Phase 1 code.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any

from osintllm import fixtures
from osintllm.agent import AgentEvent, EventCallback, OsintAgent
from osintllm.config import Settings, load_settings
from osintllm.investigation import Investigator
from osintllm.llm import CompletionResult, LLMProvider, Usage
from osintllm.report import OsintReport
from osintllm.scenarios import DEFAULT_SCENARIO_NAME, load_scenario

CONFIG_WITH_VERIFIER = "with_verifier"
CONFIG_WITHOUT_VERIFIER = "without_verifier"


@dataclass
class LLMCallRecord:
    seconds: float
    usage: Usage


class _InstrumentedProvider(LLMProvider):
    """Wrap a real provider to capture usage + latency of each call, without
    changing its behavior or the calling code."""

    def __init__(self, inner: LLMProvider) -> None:
        self._inner = inner
        self.name = inner.name
        self.calls: list[LLMCallRecord] = []

    def complete(self, **kwargs: Any) -> CompletionResult:
        t0 = time.monotonic()
        result = self._inner.complete(**kwargs)
        self.calls.append(LLMCallRecord(seconds=time.monotonic() - t0, usage=result.usage))
        return result


@dataclass
class RunRecord:
    domain: str
    config: str
    repetition: int
    provider: str
    model: str
    report: OsintReport
    initial_report: OsintReport
    verified: bool | None
    corrected: bool | None
    correction_rounds: int | None  # number of revise_report calls (None without verifier)
    events: list[AgentEvent]
    wall_seconds: float
    scenario: str = DEFAULT_SCENARIO_NAME
    llm_calls: list[LLMCallRecord] = field(default_factory=list)

    @property
    def total_usage(self) -> Usage:
        total = Usage()
        for c in self.llm_calls:
            total.prompt_tokens += c.usage.prompt_tokens
            total.completion_tokens += c.usage.completion_tokens
            total.total_tokens += c.usage.total_tokens
        return total

    @property
    def llm_seconds(self) -> float:
        return sum(c.seconds for c in self.llm_calls)


def _settings_for_eval(seed: int) -> Settings:
    """Eval path settings: forced determinism (temperature=0 + seed)."""
    base = load_settings()
    return Settings(
        provider=base.provider,
        api_key=base.api_key,
        base_url=base.base_url,
        model=base.model,
        temperature=0.0,
        seed=seed,
        max_iterations=base.max_iterations,
        request_timeout=base.request_timeout,
        max_verify_iterations=base.max_verify_iterations,
        verifier_provider=base.verifier_provider,
    )


def run_once(
    domain: str,
    config: str,
    repetition: int,
    seed: int = 42,
    scenario_name: str = DEFAULT_SCENARIO_NAME,
    on_event: EventCallback | None = None,
) -> RunRecord:
    """One full run in --replay. `config` = with_verifier | without_verifier.

    `on_event`, if provided, receives the same AgentEvents (tool_call,
    tool_result, verification…) as the live `/api/analyze` path — used to
    animate the Benchmark screen's architecture graph during the run.
    """
    os.environ["OSINTLLM_FIXTURE_MODE"] = "replay"
    fixtures.set_current_domain(domain)
    settings = _settings_for_eval(seed=seed + repetition)
    scenario = load_scenario(scenario_name)

    t0 = time.monotonic()

    if config == CONFIG_WITHOUT_VERIFIER:
        agent = OsintAgent(settings)
        instrumented = _InstrumentedProvider(agent.provider)
        agent.provider = instrumented
        result = agent.run(domain, mode="passive", scenario=scenario, on_event=on_event)
        report = result.report
        record = RunRecord(
            domain=domain,
            config=config,
            repetition=repetition,
            provider=settings.provider,
            model=settings.model,
            report=report,
            initial_report=report,
            verified=None,
            corrected=None,
            correction_rounds=None,
            events=result.events,
            wall_seconds=time.monotonic() - t0,
            scenario=scenario_name,
            llm_calls=instrumented.calls,
        )
        return record

    if config == CONFIG_WITH_VERIFIER:
        investigator = Investigator(settings)
        agent_instr = _InstrumentedProvider(investigator.agent.provider)
        investigator.agent.provider = agent_instr
        verifier_instr = _InstrumentedProvider(investigator.verifier.provider)
        investigator.verifier.provider = verifier_instr
        inv_result = investigator.run(domain, mode="passive", scenario=scenario, on_event=on_event)
        record = RunRecord(
            domain=domain,
            config=config,
            repetition=repetition,
            provider=settings.provider,
            model=settings.model,
            report=inv_result.final_report,
            initial_report=inv_result.initial_report,
            verified=inv_result.verified,
            corrected=inv_result.corrected,
            correction_rounds=inv_result.correction_rounds,
            events=inv_result.events,
            wall_seconds=time.monotonic() - t0,
            scenario=scenario_name,
            llm_calls=agent_instr.calls + verifier_instr.calls,
        )
        return record

    raise ValueError(f"unknown config: {config!r}")
