"""CLI entry point — runs the OSINT agent end to end.

Usage:
    python main.py example.com
    python main.py example.com --json      # also print the JSON report
    python main.py example.com --no-cache  # ignore the disk cache
    python main.py example.com --active    # active reconnaissance (contacts the target)
    python main.py example.com --active --proxy  # target request via Tor/proxy
    python main.py example.com --record    # record eval fixtures (evals/fixtures/)
    python main.py example.com --replay    # replay from fixtures, no tool-side network
    python main.py example.com --provider=mistral  # force the LLM provider
                                           # (default: OSINTLLM_PROVIDER)
    python main.py example.com --scenario=phishing_triage  # change the mission
                                           # (default: external_recon)
    python main.py                         # prompt for the domain interactively

The structured report is also written to reports/<domain>.json.
Requires a DeepSeek key (or Mistral, see .env.example) in .env.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Make the src/ package importable without a manual PYTHONPATH.
sys.path.insert(0, str(Path(__file__).parent / "src"))

from osintllm.agent import AgentEvent  # noqa: E402
from osintllm.config import ConfigError  # noqa: E402
from osintllm.investigation import Investigator  # noqa: E402
from osintllm.scenarios import DEFAULT_SCENARIO_NAME, ScenarioError, load_scenario  # noqa: E402

REPORTS_DIR = Path(__file__).parent / "reports"


def _print_event(event: AgentEvent) -> None:
    """Print the agents' reasoning live in the terminal."""
    if event.type == "info":
        print(f"\n[i] {event.data['message']}")
    elif event.type == "assistant_message":
        print(f"\n[assistant] {event.data['content']}")
    elif event.type == "tool_call":
        print(f"\n[tool →] {event.data['name']}({event.data['arguments']})")
    elif event.type == "tool_result":
        result = event.data["result"]
        preview = str(result)
        if len(preview) > 300:
            preview = preview[:300] + "…"
        print(f"[tool ←] {event.data['name']} : {preview}")
    elif event.type == "verification":
        verdict = "✓ verified" if event.data.get("verified") else "⚠ corrections requested"
        print(f"\n[audit] {verdict} — {event.data.get('notes', '')}")
    elif event.type == "final":
        print("\n" + "=" * 60)
        print(event.data["report"].to_markdown())


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    show_json = "--json" in argv
    mode = "active" if "--active" in argv else "passive"
    # Proxy (Tor by default): active mode only, the only mode that touches the target.
    os.environ["OSINTLLM_USE_PROXY"] = "1" if (mode == "active" and "--proxy" in argv) else "0"
    if "--no-cache" in argv:
        os.environ["OSINTLLM_NO_CACHE"] = "1"

    if "--record" in argv and "--replay" in argv:
        print("Error: --record and --replay are mutually exclusive.", file=sys.stderr)
        return 2
    if "--record" in argv:
        os.environ["OSINTLLM_FIXTURE_MODE"] = "record"
    elif "--replay" in argv:
        os.environ["OSINTLLM_FIXTURE_MODE"] = "replay"

    provider_flag = next((a for a in argv if a.startswith("--provider=")), None)
    if provider_flag:
        os.environ["OSINTLLM_PROVIDER"] = provider_flag.split("=", 1)[1].strip()

    scenario_flag = next((a for a in argv if a.startswith("--scenario=")), None)
    scenario_name = (
        scenario_flag.split("=", 1)[1].strip() if scenario_flag else DEFAULT_SCENARIO_NAME
    )
    try:
        scenario = load_scenario(scenario_name)
    except ScenarioError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    domain = args[0].strip() if args else input("Domain to analyze: ").strip()
    if not domain:
        print("No domain provided.", file=sys.stderr)
        return 2

    try:
        investigator = Investigator()
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 1

    via_proxy = os.environ.get("OSINTLLM_USE_PROXY") == "1"
    fixture_mode = os.environ.get("OSINTLLM_FIXTURE_MODE", "")
    print(
        f"[mode] {mode} reconnaissance"
        + (" · via proxy" if via_proxy else "")
        + f" · provider {investigator.settings.provider}"
        + f" · scenario {scenario.name}"
        + (f" · fixtures={fixture_mode}" if fixture_mode else "")
    )
    result = investigator.run(domain, on_event=_print_event, mode=mode, scenario=scenario)
    report = result.final_report

    # Export the 3 formats to reports/.
    REPORTS_DIR.mkdir(exist_ok=True)
    exports = {
        "json": report.to_json(),
        "md": report.to_markdown(),
        "html": report.to_html(),
    }
    for ext, content in exports.items():
        (REPORTS_DIR / f"{report.domain}.{ext}").write_text(content, encoding="utf-8")
    print(f"\n[✓] Reports written to {REPORTS_DIR}/{report.domain}.{{json,md,html}}")
    print("    (open the .html in a browser, then Cmd+P → PDF to export)")

    if show_json:
        print("\n--- JSON ---")
        print(report.to_json())

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
