"""`make eval` orchestrator (Phase 2.3): loops over domains × configs ×
repetitions in --replay, computes all Phase 2.2 metrics, writes
evals/results/<timestamp>.json + a Markdown summary.

The LLM judge (soft layer + assertions) and error injection run only once
per domain (not at every repetition): they are qualitative judgments that
are expensive in LLM calls; variance matters mostly for the quantitative
metrics (hard hallucination, completion, cost/latency), carried by the full
repetitions of the main run.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import json
import os
import sys
import threading
import traceback
from pathlib import Path
from typing import Any, Callable

from osintllm.agent import AgentEvent
from osintllm.config import Settings, load_settings
from osintllm.events import AGENT_EVENT_STDOUT_PREFIX, project_agent_event
from osintllm.scenarios import DEFAULT_SCENARIO_NAME, load_scenario
from osintllm.verifier import VerifierAgent

from . import entities, injector, judge, metrics
from .aggregate import mean_std, render_markdown_summary, to_jsonable
from .ground_truth import list_domains, load_ground_truth
from .runner import (
    CONFIG_WITH_VERIFIER,
    CONFIG_WITHOUT_VERIFIER,
    RunRecord,
    _settings_for_eval,
    run_once,
)

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"

# Receives (domain, config, repetition, AgentEvent) at each step of a task's
# agentic loop — see `_make_stdout_emitter`.
TaskEventEmitter = Callable[[str, str, int, AgentEvent], None]

# A single lock for all tasks: stdout writes come from concurrent threads
# (`run_matrix`'s ThreadPoolExecutor) and must stay complete lines, never
# interleaved.
_stdout_lock = threading.Lock()


def _make_stdout_emitter() -> TaskEventEmitter:
    """Emitter that streams each AgentEvent to stdout as prefixed JSON (see
    `AGENT_EVENT_STDOUT_PREFIX`) — read by `/api/eval/launch` (api.py) to
    animate the Benchmark screen's live graph. Only wired when
    `--stream-events` is passed (see `main`), so stdout of normal
    command-line runs is not polluted."""

    def emit(domain: str, config: str, repetition: int, event: AgentEvent) -> None:
        if event.type == "final":
            kind, data = "final", {}
        else:
            projected = project_agent_event(event)
            if projected is None:
                return
            kind, data = projected
        payload = {
            "domain": domain,
            "config": config,
            "repetition": repetition,
            "kind": kind,
            "data": data,
        }
        line = AGENT_EVENT_STDOUT_PREFIX + json.dumps(payload, ensure_ascii=False) + "\n"
        with _stdout_lock:
            sys.stdout.write(line)
            sys.stdout.flush()

    return emit


def _emit_phase(
    emit: TaskEventEmitter | None,
    domain: str,
    config: str,
    repetition: int,
    message: str,
    active: bool,
) -> None:
    """Signal the start/end of an LLM call outside the agentic loop (judge,
    injector) on the same channel as `_run_single` — reuses the "info"
    (start, with a status message) and "final" (end) kinds already
    understood by `project_agent_event` / the live graph, without inventing
    a new format."""
    if emit is None:
        return
    if active:
        emit(domain, config, repetition, AgentEvent("info", {"message": message}))
    else:
        emit(domain, config, repetition, AgentEvent("final", {}))


def _run_single(
    domain: str,
    config: str,
    repetition: int,
    seed: int,
    scenario_name: str,
    emit: TaskEventEmitter | None = None,
) -> dict[str, Any]:
    # Everything is guarded, not just the LLM call: an invalid ground truth
    # (YAML typo, etc.) must never crash the whole suite after the real run
    # has already cost LLM calls (seen in Phase 2).
    try:
        on_event = (lambda e: emit(domain, config, repetition, e)) if emit is not None else None
        record = run_once(
            domain, config, repetition, seed=seed, scenario_name=scenario_name, on_event=on_event
        )

        gt = load_ground_truth(domain)
        scenario = load_scenario(scenario_name)
        allowed_tools = set(scenario.tool_names) if scenario.tool_names is not None else None
        sub = metrics.subdomain_recall_precision(record, gt)
        orch = metrics.orchestration_efficiency(record, gt, allowed_tools=allowed_tools)
        usage = record.total_usage

        row = {
            "domain": domain,
            "config": config,
            "repetition": repetition,
            "scenario": scenario_name,
            "stopped_reason": record.report.stopped_reason,
            "completed": metrics.completed_cleanly(record),
            "risk_level": record.report.risk_level,
            "verified": record.verified,
            "corrected": record.corrected,
            "correction_rounds": record.correction_rounds,
            "hallucination_hard": entities.hallucination_rate_hard(record.report),
            # The flagged entities themselves, so that a rate change can be
            # diagnosed from the results file alone.
            "unsupported_entities": sorted(
                f"{c.entity_type}:{c.value}"
                for c in entities.extract_and_check(record.report)
                if not c.supported
            ),
            "recall": sub.recall,
            "precision": sub.precision,
            "tool_calls": orch.total_calls,
            "redundant_calls": orch.redundant_calls,
            "missed_calls": orch.missed_calls,
            "prompt_tokens": usage.prompt_tokens,
            "completion_tokens": usage.completion_tokens,
            "total_tokens": usage.total_tokens,
            "wall_seconds": record.wall_seconds,
            "llm_call_count": len(record.llm_calls),
            **metrics.attack_layer(record),
            "_record": record,  # kept for the judge/injection, removed before serialization
        }
        if scenario_name == "phishing_triage":
            row["phishing_verdict_correct"] = metrics.phishing_verdict_correct(record, gt)
        return row
    except Exception as exc:  # noqa: BLE001 — isolate the failure, don't crash the whole suite
        return {
            "domain": domain, "config": config, "repetition": repetition,
            "scenario": scenario_name,
            "error": f"{type(exc).__name__}: {exc}",
            "traceback": traceback.format_exc(),
        }


def run_matrix(
    domains: list[str],
    repetitions: int,
    seed: int,
    max_workers: int,
    scenario_name: str = DEFAULT_SCENARIO_NAME,
    emit: TaskEventEmitter | None = None,
    configs: tuple[str, ...] = (CONFIG_WITHOUT_VERIFIER, CONFIG_WITH_VERIFIER),
) -> list[dict[str, Any]]:
    tasks = [(d, c, r) for d in domains for c in configs for r in range(1, repetitions + 1)]
    results: list[dict[str, Any]] = []
    with cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {
            ex.submit(_run_single, d, c, r, seed, scenario_name, emit): (d, c, r)
            for d, c, r in tasks
        }
        for fut in cf.as_completed(futures):
            d, c, r = futures[fut]
            res = fut.result()
            results.append(res)
            status = "OK" if "error" not in res else f"ERROR: {res['error']}"
            print(f"[{d} | {c} | rep{r}] {status}", file=sys.stderr)
    return results


def _index_by_key(matrix_results: list[dict[str, Any]]) -> dict[tuple[str, str, int], dict]:
    return {
        (r["domain"], r["config"], r["repetition"]): r
        for r in matrix_results
        if "error" not in r
    }


def run_judge_pass(
    matrix_results: list[dict[str, Any]], domains: list[str], emit: TaskEventEmitter | None = None
) -> dict[str, Any]:
    """Judge (soft layer + assertions) on repetition 1 of each (domain,
    with_verifier config) — a single sequential pass per domain (no
    ThreadPoolExecutor here, unlike run_matrix)."""
    judge_provider = judge.build_judge_provider()
    out: dict[str, Any] = {}
    by_key = _index_by_key(matrix_results)
    for domain in domains:
        row = by_key.get((domain, CONFIG_WITH_VERIFIER, 1))
        if row is None:
            continue
        record: RunRecord = row["_record"]
        _emit_phase(
            emit, domain, "judge", 1, "LLM judging (deepseek-reasoner) in progress…", active=True
        )
        try:
            gt = load_ground_truth(domain)
            claims = judge.judge_report_claims(record.report, judge_provider)
            assertions = judge.judge_assertions(record.report, gt, judge_provider)
        except Exception as exc:  # noqa: BLE001
            out[domain] = {"error": f"{type(exc).__name__}: {exc}"}
            continue
        finally:
            _emit_phase(emit, domain, "judge", 1, "", active=False)
        out[domain] = {
            "claims": [to_jsonable(c) for c in claims],
            "assertions": [to_jsonable(a) for a in assertions],
        }
        n_claims, n_assert = len(claims), len(assertions)
        print(f"[judge | {domain}] {n_claims} claims, {n_assert} assertions", file=sys.stderr)
    return out


def _detection_for_domain(
    domain: str,
    record: RunRecord,
    repetitions: int,
    seed: int,
    settings: Settings,
    emit: TaskEventEmitter | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    detections: list[dict[str, Any]] = []
    false_positives: list[dict[str, Any]] = []

    try:
        gt = load_ground_truth(domain)
        families = [
            f for f in injector.FAMILIES
            if not (f == "contradicted_risk" and gt.reputation_verdict == "malicious")
        ]

        for rep in range(1, repetitions + 1):
            _emit_phase(emit, domain, "injector", rep, "False-positive check…", active=True)
            verifier = VerifierAgent(settings)
            fp = injector.run_false_positive_check(verifier, record.report)
            _emit_phase(emit, domain, "injector", rep, "", active=False)
            false_positives.append({"domain": domain, "repetition": rep, **to_jsonable(fp)})
            print(
                f"[injector | {domain} | FP | rep{rep}] false_positive={fp.false_positive}",
                file=sys.stderr,
            )

            for fam in families:
                case = injector.inject(fam, record.report, seed=seed + rep)
                if case is None:
                    continue
                _emit_phase(emit, domain, "injector", rep, f"Injecting \"{fam}\"…", active=True)
                verifier = VerifierAgent(settings)
                det = injector.run_detection(verifier, case)
                _emit_phase(emit, domain, "injector", rep, "", active=False)
                detections.append(
                    {"repetition": rep, "detail": case.detail, **to_jsonable(det)}
                )
                print(
                    f"[injector | {domain} | {fam} | rep{rep}] detected={det.detected}",
                    file=sys.stderr,
                )
    except Exception as exc:  # noqa: BLE001 — a failing domain doesn't stop the others
        print(f"[injector | {domain}] ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)

    return detections, false_positives


def run_verifier_detection(
    matrix_results: list[dict[str, Any]],
    domains: list[str],
    repetitions: int,
    seed: int,
    max_workers: int = 6,
    emit: TaskEventEmitter | None = None,
) -> dict[str, Any]:
    """Error injection + detection/false-positive measurement (Phase 2.2).

    One domain = one sequential sequence (FP then 5 families x repetitions),
    but domains run in parallel (like run_matrix)."""
    settings = _settings_for_eval(seed=seed)
    by_key = _index_by_key(matrix_results)

    eligible: list[tuple[str, RunRecord]] = []
    for domain in domains:
        row = by_key.get((domain, CONFIG_WITH_VERIFIER, 1))
        if row is None:
            continue
        record: RunRecord = row["_record"]
        if not record.verified:
            # Only inject into reports already judged faithful — otherwise we'd
            # measure detection of an ALREADY faulty report, not of the injected error.
            continue
        eligible.append((domain, record))

    detections: list[dict[str, Any]] = []
    false_positives: list[dict[str, Any]] = []
    with cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {
            ex.submit(_detection_for_domain, d, r, repetitions, seed, settings, emit): d
            for d, r in eligible
        }
        for fut in cf.as_completed(futures):
            dets, fps = fut.result()
            detections.extend(dets)
            false_positives.extend(fps)

    return {"detections": detections, "false_positives": false_positives}


def _attack_summary(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    """ATT&CK layer aggregates (None for results without the counters)."""
    rows = [r for r in rows if "attack_mappings" in r]
    if not rows:
        return None
    n = len(rows)

    def total(key: str) -> int:
        return sum(int(r.get(key, 0)) for r in rows)

    def runs_with(key: str) -> int:
        return sum(1 for r in rows if r.get(key, 0) > 0)

    return {
        "share_runs_with_mapping": runs_with("attack_mappings") / n,
        "share_runs_calling_lookup": runs_with("attack_lookup_calls") / n,
        "mappings_mean": total("attack_mappings") / n,
        "invented_ids_initial_total": total("invented_ids_initial"),
        "runs_with_invented_initial": runs_with("invented_ids_initial"),
        "invented_ids_stripped_total": total("invented_ids_stripped"),
        "invented_ids_final_total": total("invented_ids_final"),
    }


def summarize(
    matrix_results: list[dict[str, Any]],
    detection: dict[str, Any],
    domains: list[str],
    repetitions: int,
    settings: Settings,
    judge_results: dict[str, Any] | None = None,
    scenario_name: str = DEFAULT_SCENARIO_NAME,
) -> dict[str, Any]:
    by_config: dict[str, Any] = {}
    for cfg in (CONFIG_WITHOUT_VERIFIER, CONFIG_WITH_VERIFIER):
        all_rows = [r for r in matrix_results if r["config"] == cfg]
        if not all_rows:
            continue  # config not run (--configs)
        n_total = len(all_rows)
        rows = [r for r in all_rows if "error" not in r]  # runs that managed to execute
        n_ok = len(rows)
        n_errors = n_total - n_ok
        # Denominator = ALL attempts: a crash (missing fixture, exception...)
        # is not a completion, it must weigh on the rate, not silently
        # disappear from the computation.
        completion_rate = sum(1 for r in rows if r["completed"]) / n_total if n_total else 0.0
        run_error_rate = n_errors / n_total if n_total else 0.0
        h_mean, h_std = mean_std(
            [r["hallucination_hard"] for r in rows if r["hallucination_hard"] is not None]
        )
        r_mean, r_std = mean_std([r["recall"] for r in rows if r["recall"] is not None])
        p_mean, p_std = mean_std([r["precision"] for r in rows if r["precision"] is not None])
        tc_mean, _ = mean_std([float(r["tool_calls"]) for r in rows])
        rc_mean, _ = mean_std([float(r["redundant_calls"]) for r in rows])
        missed_avg = mean_std([float(len(r["missed_calls"])) for r in rows])[0] or 0.0
        tt_mean, tt_std = mean_std([float(r["total_tokens"]) for r in rows])
        ws_mean, ws_std = mean_std([r["wall_seconds"] for r in rows])
        cr_values = [
            float(r["correction_rounds"])
            for r in rows
            # missing from pre-instrumentation results
            if r.get("correction_rounds") is not None
        ]
        cr_mean, cr_std = mean_std(cr_values)
        by_config[cfg] = {
            "n_runs_attempted": n_total,
            "n_runs_ok": n_ok,
            "n_runs_errored": n_errors,
            "run_error_rate": run_error_rate,
            "completion_rate": completion_rate,
            "hallucination_hard_mean": h_mean, "hallucination_hard_std": h_std,
            "recall_mean": r_mean, "recall_std": r_std,
            "precision_mean": p_mean, "precision_std": p_std,
            "tool_calls_mean": tc_mean, "redundant_calls_mean": rc_mean,
            "missed_calls_avg_count": missed_avg,
            "total_tokens_mean": tt_mean, "total_tokens_std": tt_std,
            "wall_seconds_mean": ws_mean, "wall_seconds_std": ws_std,
            "correction_rounds_mean": cr_mean, "correction_rounds_std": cr_std,
            "attack": _attack_summary(rows),
        }

    by_family: dict[str, float] = {}
    for fam in injector.FAMILIES:
        fam_dets = [d for d in detection["detections"] if d["family"] == fam]
        rate, _ = mean_std([1.0 if d["detected"] else 0.0 for d in fam_dets])
        by_family[fam] = rate or 0.0
    fp_values = [1.0 if f["false_positive"] else 0.0 for f in detection["false_positives"]]
    fp_rate, _ = mean_std(fp_values)

    phishing_verdict: dict[str, Any] | None = None
    if scenario_name == "phishing_triage":
        verdicts = [
            r["phishing_verdict_correct"]
            for r in matrix_results
            if "error" not in r and r.get("phishing_verdict_correct") is not None
        ]
        n_judged = len(verdicts)
        accuracy = (sum(1 for v in verdicts if v) / n_judged) if n_judged else None
        phishing_verdict = {"n_judged": n_judged, "accuracy": accuracy}

    return {
        "meta": {
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "provider": settings.provider,
            "model": settings.model,
            "scenario": scenario_name,
            "n_domains": len(domains),
            "n_repetitions": repetitions,
            "attack_rag": settings.attack_rag,
        },
        "by_config": by_config,
        # None when the detection pass was skipped (--no-detection): an
        # empty pass must not read as a 0% detection rate.
        "verifier_detection": (
            {"by_family": by_family, "false_positive_rate": fp_rate or 0.0}
            if detection["detections"] or detection["false_positives"]
            else None
        ),
        "judge_soft": (
            judge.summarize_verdicts(judge_results) if judge_results is not None else None
        ),
        "phishing_verdict": phishing_verdict,
    }


def _strip_records(matrix_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{k: v for k, v in r.items() if k != "_record"} for r in matrix_results]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="osintllm eval harness (Phase 2)")
    parser.add_argument(
        "--domains", nargs="*", default=None, help="Subset of domains (default: all)"
    )
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-workers", type=int, default=6)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument(
        "--scenario",
        default=DEFAULT_SCENARIO_NAME,
        help=(
            "Evaluated scenario (default: external_recon, historical behavior). "
            "The error injector and the LLM judge remain designed for external_recon "
            "— see evals/DATASET.md."
        ),
    )
    parser.add_argument(
        "--stream-events",
        action="store_true",
        help=(
            "Emit each AgentEvent (tool_call, tool_result, verification…) on "
            "stdout as prefixed JSON (see AGENT_EVENT_STDOUT_PREFIX) — meant to "
            "be read by /api/eval/launch (api.py), not for manual runs."
        ),
    )
    parser.add_argument(
        "--attack-rag",
        choices=("on", "off"),
        default=None,
        help="Force the ATT&CK layer on/off (default: OSINTLLM_ATTACK_RAG, on).",
    )
    parser.add_argument(
        "--configs",
        nargs="+",
        choices=(CONFIG_WITHOUT_VERIFIER, CONFIG_WITH_VERIFIER),
        default=[CONFIG_WITHOUT_VERIFIER, CONFIG_WITH_VERIFIER],
        help="Configurations to run (default: both).",
    )
    parser.add_argument(
        "--no-judge", action="store_true", help="Skip the LLM-as-judge pass (saves calls)."
    )
    parser.add_argument(
        "--no-detection",
        action="store_true",
        help="Skip the verifier error-injection detection pass (saves calls).",
    )
    args = parser.parse_args(argv)

    if args.attack_rag is not None:
        # Read by load_settings() in every run (_settings_for_eval).
        os.environ["OSINTLLM_ATTACK_RAG"] = "1" if args.attack_rag == "on" else "0"
    domains = args.domains or list_domains()
    settings = load_settings()

    print(
        f"Domains: {len(domains)} · repetitions: {args.repetitions} · "
        f"scenario: {args.scenario} · provider: {settings.provider}/{settings.model}",
        file=sys.stderr,
    )

    emit = _make_stdout_emitter() if args.stream_events else None
    matrix_results = run_matrix(
        domains, args.repetitions, args.seed, args.max_workers, args.scenario, emit=emit,
        configs=tuple(args.configs),
    )
    judge_results = (
        None if args.no_judge else run_judge_pass(matrix_results, domains, emit=emit)
    )
    detection = (
        {"detections": [], "false_positives": []}
        if args.no_detection
        else run_verifier_detection(
            matrix_results, domains, args.repetitions, args.seed, args.max_workers, emit=emit
        )
    )
    summary = summarize(
        matrix_results,
        detection,
        domains,
        args.repetitions,
        settings,
        judge_results,
        scenario_name=args.scenario,
    )

    payload = {
        "summary": summary,
        "runs": _strip_records(matrix_results),
        "judge": judge_results,
        "verifier_detection": detection,
    }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = f"{dt.datetime.now(dt.timezone.utc):%Y%m%d_%H%M%S}"
    out_path = args.out or RESULTS_DIR / f"{stamp}.json"
    out_path.write_text(
        json.dumps(to_jsonable(payload), ensure_ascii=False, indent=2), encoding="utf-8"
    )

    md = render_markdown_summary(summary)
    (out_path.with_suffix(".md")).write_text(md, encoding="utf-8")

    print(f"\nResults written to {out_path} and {out_path.with_suffix('.md')}", file=sys.stderr)
    print("\n" + md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
