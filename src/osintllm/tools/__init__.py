"""Registry of the tools available to the agent.

To add a tool: import it and append it to the `ALL_TOOLS` list.
"""

from __future__ import annotations

from .asn_lookup_tool import asn_lookup_tool
from .attack_lookup_tool import attack_lookup_tool
from .base import Tool
from .crtsh_tool import crtsh_tool
from .dns_records_tool import dns_records_tool
from .github_search_tool import github_search_tool
from .ipgeo_tool import ipgeo_tool
from .tech_fingerprint_tool import tech_fingerprint_tool
from .virustotal_tool import virustotal_tool
from .wayback_tool import wayback_tool
from .whois_tool import whois_tool

# Order = indicative priority order exposed to the LLM.
ALL_TOOLS: list[Tool] = [
    whois_tool,
    dns_records_tool,
    crtsh_tool,
    ipgeo_tool,
    asn_lookup_tool,
    wayback_tool,
    tech_fingerprint_tool,
    github_search_tool,
    virustotal_tool,
    # Last: maps the findings of the tools above to MITRE ATT&CK techniques.
    attack_lookup_tool,
]

# Name -> tool index, used to dispatch calls from the agent loop.
TOOLS_BY_NAME: dict[str, Tool] = {t.name: t for t in ALL_TOOLS}

# Reconnaissance modes offered to the user.
#  - "passive": passive tools only (no direct contact with the target).
#  - "active":  all tools, including those that contact the target.
RECON_MODES = ("passive", "active")
DEFAULT_MODE = "passive"


def tools_for_mode(mode: str = DEFAULT_MODE) -> list[Tool]:
    """Tools allowed for a reconnaissance mode.

    In passive mode, tools that contact the target directly (`passive=False`)
    are excluded; in active mode, every tool is available.
    """
    if mode == "active":
        return list(ALL_TOOLS)
    return [t for t in ALL_TOOLS if t.passive]


def tool_specs(mode: str = DEFAULT_MODE) -> list[dict]:
    """Schemas of the tools allowed for `mode`, in the format DeepSeek expects."""
    return [t.spec() for t in tools_for_mode(mode)]


__all__ = [
    "ALL_TOOLS",
    "TOOLS_BY_NAME",
    "RECON_MODES",
    "DEFAULT_MODE",
    "tools_for_mode",
    "tool_specs",
    "Tool",
]
