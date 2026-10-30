"""Data of the backend-less web demo (`make demo`, see web/src/lib/api.js).

Two commands:

    python scripts/demo_data.py record wikipedia.org mozilla.org:email_security_posture
        Runs a REAL analysis per target (LLM quota, OSINT requests) through the
        same SSE generator as `/api/analyze`, timestamps every event and saves
        the stream to web/public-demo/demo-data/analyses/. The demo replays
        these recordings with their original rhythm. `domain:scenario`
        picks the scenario (default: external_recon). Recordings are
        committed: re-recording is a deliberate, paid action.

    python scripts/demo_data.py export
        Free. Copies the eval runs (evals/results/), the eval domain list and
        a settings snapshot taken from the latest recording into
        web/public-demo/demo-data/, in the exact shape the API routes return.
        Run by `make demo` before every demo build; its output is gitignored.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

import api  # noqa: E402

DEMO_DATA = _ROOT / "web" / "public-demo" / "demo-data"
ANALYSES = DEMO_DATA / "analyses"
INDEX = ANALYSES / "index.json"

_SSE_RE = re.compile(r"^event: (?P<event>[^\n]+)\ndata: (?P<data>.*)\n\n$", re.DOTALL)


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def _load_index() -> list[dict[str, Any]]:
    return json.loads(INDEX.read_text(encoding="utf-8")) if INDEX.is_file() else []


def record(target: str) -> None:
    domain, _, scenario = target.partition(":")
    scenario = scenario or api.DEFAULT_SCENARIO_NAME
    if scenario not in api.list_scenarios():
        raise SystemExit(f"Unknown scenario: {scenario}")

    settings = api.get_active_settings()
    print(f"→ recording {domain} [{scenario}] with {settings['active'].get('model')}…", flush=True)
    events: list[dict[str, Any]] = []
    start = time.monotonic()
    for chunk in api._event_stream(domain, True, "passive", False, scenario, None):
        match = _SSE_RE.match(chunk)
        if match is None:
            continue  # keepalive comment
        event = match["event"]
        events.append(
            {
                "t": round(time.monotonic() - start, 2),
                "event": event,
                "data": json.loads(match["data"]),
            }
        )
        print(f"  {events[-1]['t']:7.1f}s  {event}", flush=True)
        if event == "error":
            raise SystemExit(f"Analysis failed, nothing saved: {events[-1]['data']}")
    if not events or events[-1]["event"] != "report":
        raise SystemExit("No final report received, nothing saved.")

    recorded_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    file = f"{scenario}__{domain}.json"
    _write_json(
        ANALYSES / file,
        {"domain": domain, "scenario": scenario, "recorded_at": recorded_at,
         "settings": settings, "events": events},
    )
    index = [e for e in _load_index() if not (e["domain"] == domain and e["scenario"] == scenario)]
    index.append(
        {
            "domain": domain,
            "scenario": scenario,
            "file": file,
            "recorded_at": recorded_at,
            "provider": settings["active"].get("provider"),
            "model": settings["active"].get("model"),
            "duration_s": events[-1]["t"],
        }
    )
    index.sort(key=lambda e: (e["scenario"], e["domain"]))
    _write_json(INDEX, index)
    print(f"✓ {file} ({len(events)} events, {events[-1]['t']:.0f}s)")


def export() -> None:
    runs = api.list_eval_runs()
    _write_json(DEMO_DATA / "eval" / "runs.json", runs)
    for run in runs:
        _write_json(DEMO_DATA / "eval" / "runs" / f"{run['id']}.json", api.get_eval_run(run["id"]))
    _write_json(DEMO_DATA / "eval" / "domains.json", api.eval_domains())

    index = _load_index()
    if not index:
        raise SystemExit("No recorded analysis: run `record` first.")
    latest = max(index, key=lambda e: e["recorded_at"])
    recording = json.loads((ANALYSES / latest["file"]).read_text(encoding="utf-8"))
    _write_json(DEMO_DATA / "settings.json", recording["settings"])
    target = DEMO_DATA.relative_to(_ROOT)
    print(f"✓ {len(runs)} eval runs, {len(index)} recorded analyses → {target}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    rec = sub.add_parser("record", help="record real analyses (costs LLM quota)")
    rec.add_argument("targets", nargs="+", metavar="domain[:scenario]")
    sub.add_parser("export", help="export eval runs and settings (free)")
    args = parser.parse_args()
    if args.command == "record":
        for target in args.targets:
            record(target)
    else:
        export()


if __name__ == "__main__":
    main()
