"""Declarative scenarios — loading of missions defined in YAML
(`scenarios/<name>.yaml`).

A scenario declares, without touching the agent loop code:
  - the specific mission (injected into the system prompt, see agent.py);
  - the subset of tools exposed to the LLM (None = no restriction, all tools
    of the passive/active mode);
  - the section titles expected in `summary` (report structure);
  - an optional risk_level -> business verdict mapping (only used by
    `phishing_triage`, purely for the prompt and display — the report's
    `risk_level` field is unchanged);
  - an optional iteration budget (None = inherits `Settings.max_iterations`).

`external_recon` is the default scenario (see
tests/test_scenarios.py::test_external_recon_prompt_unchanged_since_phase_3).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from .tools import Tool, tools_for_mode

DEFAULT_SCENARIO_NAME = "external_recon"


def _scenarios_dir() -> Path:
    return Path(os.getenv("OSINTLLM_SCENARIOS_DIR", "scenarios"))


class ScenarioError(RuntimeError):
    """Unknown scenario or invalid YAML file."""


@dataclass(frozen=True)
class Scenario:
    """A declarative mission for the agent (see module docstring)."""

    name: str
    label: str
    mission: str
    tool_names: tuple[str, ...] | None
    report_sections: tuple[str, ...]
    risk_level_mapping: dict[str, str] | None
    max_iterations: int | None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Scenario":
        tools = data.get("tools")
        return cls(
            name=data["name"],
            label=data["label"],
            mission=data["mission"],
            tool_names=tuple(tools) if tools is not None else None,
            report_sections=tuple(data.get("report_sections") or []),
            risk_level_mapping=data.get("risk_level_mapping"),
            max_iterations=data.get("max_iterations"),
        )


@lru_cache(maxsize=None)
def load_scenario(name: str) -> Scenario:
    """Load `scenarios/<name>.yaml`. Raise ScenarioError if missing/invalid."""
    path = _scenarios_dir() / f"{name}.yaml"
    if not path.exists():
        raise ScenarioError(
            f"Unknown scenario: {name!r}. Available: {', '.join(list_scenarios())}"
        )
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    scenario = Scenario.from_dict(data)
    if scenario.name != name:
        raise ScenarioError(
            f"scenarios/{name}.yaml declares name={scenario.name!r} (inconsistent)."
        )
    return scenario


def list_scenarios() -> tuple[str, ...]:
    """Names of the available scenarios (names of the scenarios/*.yaml files)."""
    return tuple(sorted(p.stem for p in _scenarios_dir().glob("*.yaml")))


def default_scenario() -> Scenario:
    return load_scenario(DEFAULT_SCENARIO_NAME)


def tools_for(mode: str, scenario: Scenario) -> list[Tool]:
    """Tools allowed for `mode` AND restricted to `scenario.tool_names`.

    `scenario.tool_names is None` means "no restriction": the default
    scenario (`external_recon`) gets exactly `tools_for_mode(mode)`.
    """
    base = tools_for_mode(mode)
    if scenario.tool_names is None:
        return base
    allowed = set(scenario.tool_names)
    return [t for t in base if t.name in allowed]


__all__ = [
    "DEFAULT_SCENARIO_NAME",
    "Scenario",
    "ScenarioError",
    "load_scenario",
    "list_scenarios",
    "default_scenario",
    "tools_for",
]
