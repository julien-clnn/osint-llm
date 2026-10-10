"""HTTP API of the OSINT agent — backend for the React frontend.

Main route: `GET /api/analyze`, which runs the agent on a domain and
**streams** its reasoning live (Server-Sent Events). Each step of the ReAct
loop (info, message, tool call, result) is pushed to the browser as it
happens; the final `report` event carries the full report (analysis + facts +
JSON/Markdown/HTML exports).

The (blocking) agent runs in a thread; it feeds a queue drained by the SSE
generator. In production, this same server also serves the static React
build (web/dist folder).

Dev launch:
    .venv/bin/uvicorn api:app --reload --port 8000
"""

from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

_ROOT = Path(__file__).resolve().parent
# Make src/ (osintllm package) and the root (evals package) importable
# without a manual PYTHONPATH — same trick as evals/run_eval.py.
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

from osintllm import cache as osint_cache  # noqa: E402
from osintllm import http as osint_http  # noqa: E402
from osintllm.agent import AgentEvent  # noqa: E402
from osintllm.config import (  # noqa: E402
    DEEPSEEK_BASE_URL,
    DEEPSEEK_MODEL,
    DEFAULT_PROVIDER,
    MISTRAL_BASE_URL,
    MISTRAL_MODEL,
    PROVIDERS,
    ConfigError,
    load_settings,
)
from osintllm.events import AGENT_EVENT_STDOUT_PREFIX, project_agent_event  # noqa: E402
from osintllm.investigation import Investigator, InvestigationResult  # noqa: E402
from osintllm.report import OsintReport, normalize_risk_level  # noqa: E402
from osintllm.scenarios import (  # noqa: E402
    DEFAULT_SCENARIO_NAME,
    list_scenarios,
    load_scenario,
)
from osintllm.tools import DEFAULT_MODE, RECON_MODES  # noqa: E402
from osintllm.tools.whois_tool import _DOMAIN_RE, _normalize_domain  # noqa: E402

from evals.harness.cli import RESULTS_DIR  # noqa: E402
from evals.harness.ground_truth import list_domains  # noqa: E402

app = FastAPI(title="osintllm API", docs_url=None, redoc_url=None)

# In dev, the frontend runs on the Vite server (port 5173) and calls the API here.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_methods=["GET"],
    allow_headers=["*"],
)

# No authentication: the API (LLM quota, active scans) only answers local
# clients unless explicitly opened with OSINTLLM_ALLOW_REMOTE=1.
_LOCAL_CLIENTS = {"127.0.0.1", "::1", "localhost", "testclient"}
_LOCAL_HOSTNAMES = {"localhost", "127.0.0.1", "::1"}


@app.middleware("http")
async def _local_only(request: Request, call_next):
    remote_ok = os.getenv("OSINTLLM_ALLOW_REMOTE", "").lower() in ("1", "true", "yes")
    host = request.client.host if request.client else ""
    if not remote_ok and host not in _LOCAL_CLIENTS:
        return JSONResponse({"detail": "Remote access disabled."}, status_code=403)
    # A loopback client can still be a browser driven by a remote page:
    # refuse cross-site requests (CORS does not block a simple GET).
    origin = request.headers.get("origin")
    cross_site = request.headers.get("sec-fetch-site") == "cross-site" or (
        origin is not None and urlsplit(origin).hostname not in _LOCAL_HOSTNAMES
    )
    if not remote_ok and cross_site:
        return JSONResponse({"detail": "Cross-site request refused."}, status_code=403)
    return await call_next(request)


_DIST = Path(__file__).resolve().parent / "web" / "dist"


def _report_payload(report: OsintReport) -> dict[str, Any]:
    """Full report for the frontend: analysis, useful facts, ready-made exports."""
    return {
        "domain": report.domain,
        "summary": report.summary,
        "risk_level": report.risk_level,
        "risk_justification": report.risk_justification,
        "recommendations": report.recommendations,
        "subdomains": report.subdomains(),
        "subdomain_total": report.subdomain_total(),
        "locations": report.locations(),
        "asn": report.asn_lookups(),
        "github": report.github_findings(),
        "iterations": report.iterations,
        "stopped_reason": report.stopped_reason,
        "exports": {
            "json": report.to_json(),
            "markdown": report.to_markdown(),
            "html": report.to_html(),
        },
    }


def _investigation_payload(result: InvestigationResult) -> dict[str, Any]:
    """Final payload: verified report + audit trail + initial report."""
    payload = _report_payload(result.final_report)
    payload["mode"] = result.mode
    scenario = result.scenario
    if scenario is not None:
        payload["scenario"] = {"name": scenario.name, "label": scenario.label}
        if scenario.risk_level_mapping:
            payload["verdict_label"] = scenario.risk_level_mapping.get(
                normalize_risk_level(result.final_report.risk_level)
            )
    initial = result.initial_report
    payload["verification"] = {
        "verified": result.verified,
        "corrected": result.corrected,
        "iterations": len(result.verifications),
        "unsupported_claims": [
            c for v in result.verifications for c in v.unsupported_claims
        ],
        "corrections": [c for v in result.verifications for c in v.corrections],
        "notes": result.verifications[-1].notes if result.verifications else "",
        # Claims still flagged by the LAST audit pass (non-empty only when the
        # final report is not verified).
        "remaining_unsupported_claims": (
            []
            if result.verified or not result.verifications
            else result.verifications[-1].unsupported_claims
        ),
    }
    # Initial report (before verification), only useful if it was corrected.
    payload["initial"] = {
        "summary": initial.summary,
        "risk_level": initial.risk_level,
        "risk_justification": initial.risk_justification,
        "recommendations": initial.recommendations,
    }
    return payload


def _sse(event: str, data: dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


# Cap on concurrent analyses: each one consumes real LLM quota.
_MAX_CONCURRENT_ANALYSES = 3
_analysis_slots = threading.BoundedSemaphore(_MAX_CONCURRENT_ANALYSES)


def _event_stream(
    domain: str,
    use_cache: bool,
    mode: str,
    use_proxy: bool,
    scenario_name: str,
    provider: str | None,
) -> Iterator[str]:
    """SSE generator: runs the agent in a thread and relays its events."""
    q: queue.Queue[tuple[str, dict[str, Any]] | None] = queue.Queue()
    scenario = load_scenario(scenario_name)

    def worker() -> None:
        # Per-thread overrides (ContextVar), never the process env: concurrent
        # analyses must not see each other's cache/proxy settings. Proxy only
        # relevant in active mode (the only mode that touches the target).
        osint_cache.set_enabled_override(use_cache)
        osint_http.set_proxy_override(mode == "active" and use_proxy)
        try:
            # `provider` picks the provider for THIS analysis only (Analysis
            # screen selector) without ever touching .env.
            investigator = Investigator(settings=load_settings(provider))
        except ConfigError as exc:
            _analysis_slots.release()
            q.put(("error", {"message": str(exc)}))
            q.put(None)
            return

        def on_event(event: AgentEvent) -> None:
            projected = project_agent_event(event)
            if projected is not None:
                q.put(projected)

        try:
            result = investigator.run(domain, on_event=on_event, mode=mode, scenario=scenario)
            report_payload = _investigation_payload(result)
            report_payload["proxy"] = mode == "active" and use_proxy
            q.put(("report", report_payload))
        except Exception as exc:  # noqa: BLE001 — surface any error
            q.put(("error", {"message": f"Error during analysis: {exc}"}))
        finally:
            _analysis_slots.release()
            q.put(None)

    if not _analysis_slots.acquire(blocking=False):
        yield _sse("error", {"message": "Too many analyses running, retry in a moment."})
        return
    threading.Thread(target=worker, daemon=True).start()

    yield _sse(
        "start",
        {
            "domain": domain,
            "mode": mode,
            "proxy": mode == "active" and use_proxy,
            "scenario": {"name": scenario.name, "label": scenario.label},
        },
    )
    # Heartbeat: an analysis can stay silent for 30-60 s (crt.sh fetch, LLM
    # thinking). Without bytes, the browser/proxies consider the connection
    # dead and drop it. So we emit an SSE comment (ignored by EventSource)
    # while the queue is empty, to keep the stream alive.
    while True:
        try:
            item = q.get(timeout=10)
        except queue.Empty:
            yield ": keepalive\n\n"
            continue
        if item is None:
            break
        event_name, data = item
        yield _sse(event_name, data)


@app.get("/api/analyze")
def analyze(
    domain: str,
    cache: bool = True,
    mode: str = DEFAULT_MODE,
    proxy: bool = False,
    scenario: str = DEFAULT_SCENARIO_NAME,
    provider: str | None = None,
) -> StreamingResponse:
    """Stream the OSINT analysis of `domain` as Server-Sent Events.

    `mode` is "passive" (default) or "active"; any other value falls back to
    passive mode, the most cautious. `proxy=true` routes the request that
    touches the target through the configured proxy (Tor by default) —
    ignored outside active mode. `scenario` picks the mission (default:
    external reconnaissance); any unknown value falls back to that default.
    `provider` forces "deepseek" or "mistral" for this analysis only
    (Analysis screen selector) without ever modifying `.env`; when omitted or
    invalid, the `.env` default provider is used.
    """
    clean_domain = _normalize_domain(domain)
    if not _DOMAIN_RE.match(clean_domain):
        raise HTTPException(status_code=400, detail=f"Invalid domain name: {domain[:100]!r}")
    resolved_mode = mode if mode in RECON_MODES else DEFAULT_MODE
    resolved_scenario = scenario if scenario in list_scenarios() else DEFAULT_SCENARIO_NAME
    resolved_provider = provider if provider in PROVIDERS else None
    return StreamingResponse(
        _event_stream(
            clean_domain, cache, resolved_mode, proxy, resolved_scenario, resolved_provider
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable buffering (nginx & co.)
        },
    )


_RUN_ID_RE = re.compile(r"^\d{8}_\d{6}$")


def _run_summary_payload(run_id: str, summary: dict[str, Any]) -> dict[str, Any]:
    """Reduce a run `summary` to what the list displays (evals/results/)."""
    meta = summary.get("meta", {})
    with_verifier = summary.get("by_config", {}).get("with_verifier") or {}
    return {
        "id": run_id,
        "generated_at": meta.get("generated_at"),
        "provider": meta.get("provider"),
        "model": meta.get("model"),
        "scenario": meta.get("scenario"),
        "n_domains": meta.get("n_domains"),
        "n_repetitions": meta.get("n_repetitions"),
        "hallucination_hard_with": with_verifier.get("hallucination_hard_mean"),
        "hallucination_hard_std_with": with_verifier.get("hallucination_hard_std"),
        "run_error_rate_with": with_verifier.get("run_error_rate"),
        # Basis for the Benchmark screen cost estimate (mean tokens/time per
        # domain×repetition pair, with-verifier config).
        "total_tokens_mean_with": with_verifier.get("total_tokens_mean"),
        "wall_seconds_mean_with": with_verifier.get("wall_seconds_mean"),
    }


@app.get("/api/eval/runs")
def list_eval_runs() -> list[dict[str, Any]]:
    """List eval harness runs (`evals/results/*.json`), most recent first."""
    if not RESULTS_DIR.is_dir():
        return []
    runs = []
    for path in sorted(RESULTS_DIR.glob("*.json"), reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            runs.append(_run_summary_payload(path.stem, data.get("summary", {})))
        except (json.JSONDecodeError, OSError):
            continue  # corrupt file or still being written: skip it
    return runs


@app.get("/api/eval/runs/{run_id}")
def get_eval_run(run_id: str) -> dict[str, Any]:
    """Run details (full summary: metrics, detection, judgment)."""
    if not _RUN_ID_RE.match(run_id):
        raise HTTPException(status_code=404, detail="Run not found.")
    path = RESULTS_DIR / f"{run_id}.json"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Run not found.")
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("summary", {})


@app.get("/api/eval/domains")
def eval_domains() -> list[str]:
    """The 15 eval dataset domains (evals/DATASET.md), for the selector."""
    return list_domains()


_PROVIDER_DEFAULTS = {
    "deepseek": (
        "DEEPSEEK_API_KEY", "DEEPSEEK_BASE_URL", DEEPSEEK_BASE_URL,
        "DEEPSEEK_MODEL", DEEPSEEK_MODEL,
    ),
    "mistral": (
        "MISTRAL_API_KEY", "MISTRAL_BASE_URL", MISTRAL_BASE_URL,
        "MISTRAL_MODEL", MISTRAL_MODEL,
    ),
}


def _provider_status(name: str) -> dict[str, Any]:
    key_var, base_var, default_base, model_var, default_model = _PROVIDER_DEFAULTS[name]
    return {
        "configured": bool(os.getenv(key_var, "").strip()),
        "model": os.getenv(model_var, default_model).strip(),
        "base_url": os.getenv(base_var, default_base).strip(),
    }


@app.get("/api/settings")
def get_active_settings() -> dict[str, Any]:
    """Local `.env` status — read-only, never the keys themselves (see
    decision: no .env editing from the site for now). Shows the active
    provider *and* what is available (key present or not) for each known
    provider."""
    try:
        settings = load_settings()
        active = {
            "provider": settings.provider,
            "model": settings.model,
            "base_url": settings.base_url,
            "temperature": settings.temperature,
            "seed": settings.seed,
            "max_verify_iterations": settings.max_verify_iterations,
            "request_timeout": settings.request_timeout,
            "configured": True,
        }
    except ConfigError as exc:
        provider = os.getenv("OSINTLLM_PROVIDER", DEFAULT_PROVIDER).strip().lower()
        if provider not in PROVIDERS:
            provider = DEFAULT_PROVIDER
        active = {"provider": provider, "model": None, "configured": False, "error": str(exc)}

    return {
        "active": active,
        "providers": {name: _provider_status(name) for name in PROVIDERS},
    }


# One benchmark at a time: each run consumes real LLM quota, two concurrent
# runs would fight over the same budget/rate limit.
_benchmark_lock = threading.Lock()

_MAX_REPETITIONS = 10
_MAX_WORKERS = 16


def _benchmark_stream(
    domains: list[str],
    repetitions: int,
    seed: int,
    max_workers: int,
    scenario: str,
    provider: str | None,
) -> Iterator[str]:
    if not _benchmark_lock.acquire(blocking=False):
        yield _sse("error", {"message": "A benchmark is already running."})
        return

    try:
        cmd = [
            sys.executable,
            "-u",  # unbuffered stdout: otherwise progress lines only reach
            # the frontend in a single chunk at the end of the process.
            str(_ROOT / "evals" / "run_eval.py"),
            "--repetitions", str(repetitions),
            "--seed", str(seed),
            "--max-workers", str(max_workers),
            "--scenario", scenario,
            # Makes each task emit its AgentEvents (tool_call, tool_result, …)
            # on stdout as prefixed JSON — feeds the Benchmark screen live
            # graph (see the read loop just below).
            "--stream-events",
        ]
        if domains:
            cmd += ["--domains", *domains]

        # Don't inherit a setting left by an ongoing analysis
        # (/api/analyze toggles these variables for the duration of its request).
        env = os.environ.copy()
        env.pop("OSINTLLM_NO_CACHE", None)
        env.pop("OSINTLLM_USE_PROXY", None)
        if provider:
            # One-off provider choice for THIS run (Benchmark screen
            # selector): isolated to the subprocess environment, never
            # written to .env.
            env["OSINTLLM_PROVIDER"] = provider

        before = set(RESULTS_DIR.glob("*.json")) if RESULTS_DIR.is_dir() else set()

        yield _sse(
            "start",
            {
                "domains": domains or list_domains(),
                "repetitions": repetitions,
                "scenario": scenario,
            },
        )

        proc = subprocess.Popen(
            cmd,
            cwd=str(_ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert proc.stdout is not None
        try:
            for line in proc.stdout:
                line = line.rstrip("\n")
                if not line:
                    continue
                if line.startswith(AGENT_EVENT_STDOUT_PREFIX):
                    try:
                        payload = json.loads(line[len(AGENT_EVENT_STDOUT_PREFIX):])
                    except json.JSONDecodeError:
                        continue  # corrupt event line (concurrent write): ignored
                    yield _sse("task", payload)
                else:
                    yield _sse("log", {"line": line})
        finally:
            returncode = proc.wait()

        if returncode != 0:
            yield _sse("error", {"message": f"The harness failed (exit code {returncode})."})
            return

        after = set(RESULTS_DIR.glob("*.json")) if RESULTS_DIR.is_dir() else set()
        new_files = sorted(after - before)
        run_id = new_files[0].stem if new_files else None
        yield _sse("done", {"run_id": run_id})
    finally:
        _benchmark_lock.release()


@app.get("/api/eval/launch")
def launch_eval(
    domains: list[str] | None = Query(None),
    repetitions: int = 3,
    seed: int = 42,
    max_workers: int = 6,
    scenario: str = DEFAULT_SCENARIO_NAME,
    provider: str | None = None,
) -> StreamingResponse:
    """Run `evals/run_eval.py` as a subprocess and stream its output (SSE).

    Consumes real LLM quota (see docs/EVAL_PLAN.md) — the frontend must ask
    for explicit confirmation before calling this route. `provider` forces
    "deepseek" or "mistral" for this run only (isolated to the subprocess
    environment, never written to `.env`); when omitted, the `.env` default
    provider is used.
    """
    known_domains = set(list_domains())
    if domains:
        unknown = [d for d in domains if d not in known_domains]
        if unknown:
            raise HTTPException(400, f"Unknown domains: {', '.join(unknown)}")
    if scenario not in list_scenarios():
        raise HTTPException(400, f"Unknown scenario: {scenario}")
    if not (1 <= repetitions <= _MAX_REPETITIONS):
        raise HTTPException(400, f"repetitions must be between 1 and {_MAX_REPETITIONS}.")
    if not (1 <= max_workers <= _MAX_WORKERS):
        raise HTTPException(400, f"max_workers must be between 1 and {_MAX_WORKERS}.")
    if provider is not None and provider not in PROVIDERS:
        raise HTTPException(400, f"Unknown provider: {provider}")

    return StreamingResponse(
        _benchmark_stream(domains or [], repetitions, seed, max_workers, scenario, provider),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# Serve the React build if present (mounted last so it doesn't shadow /api).
if _DIST.is_dir():
    app.mount("/", StaticFiles(directory=str(_DIST), html=True), name="web")
