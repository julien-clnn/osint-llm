"""SOFT hallucination-detection layer: LLM-as-judge (Phase 2.2).

The judge receives ONLY the run's tool observations as allowed context
(never the ground truth, never the evaluated agent's reasoning) and audits
two things:

1. `judge_report_claims` — the report's natural-language claims
   (summary/risk_justification/recommendations), one verdict per claim
   (`supported` / `unsupported` / `contradicted`) + a short justification.
   This is the soft hallucination layer proper (see entities.py for the
   hard layer, on literal entities).
2. `judge_assertions` — the ground truth `must_contain`/`must_not_contain`
   assertions (evals/ground_truth/<domain>.yaml), to check that the report
   actually reflects the expected facts.

The judge ALWAYS runs on `deepseek-reasoner` (see `build_judge_provider`),
whatever the evaluated provider (DeepSeek or Mistral): a constant judge
avoids self-evaluation AND makes scores comparable across providers — a
judge that follows the evaluated provider would be a confounding variable in
any DeepSeek/Mistral comparison. `deepseek-reasoner` does not support forced
`tool_choice` ("thinking mode does not support this tool_choice", verified
empirically): we use `tool_choice="auto"` with a strict instruction, and
treat a missing tool_call as an explicit judging failure rather than a
silent fallback.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Literal

from openai import APITimeoutError

import os

from osintllm.config import DEEPSEEK_BASE_URL, ConfigError, Settings, load_settings
from osintllm.llm import LLMProvider, ToolCallRequest, build_provider
from osintllm.report import OsintReport

from .ground_truth import GroundTruth

JUDGE_MODEL_DEFAULT = "deepseek-reasoner"

# deepseek-reasoner ("thinking mode") is much slower than the evaluated model
# (deepseek-chat), especially on domains with large contexts (e.g.
# service-public.fr: ~750k tokens/run with verifier). The default Settings
# request_timeout (30s, designed for deepseek-chat) times out on those
# domains — seen in Phase 2 (5/15 domains without a verdict on the first
# full run). The judge needs its own time budget.
JUDGE_REQUEST_TIMEOUT = 180.0
_MAX_RETRIES = 2

CLAIMS_JUDGE_SYSTEM_PROMPT = """\
You are an independent auditor. You are given ONLY raw OSINT tool \
observations (JSON) and a list of natural-language claims extracted from a \
report written by another system. You have access to NO other source: never \
use general knowledge about the domain under study, only the observations \
provided.

For EACH claim, return a verdict:
- "supported" if it is directly backed by at least one observation;
- "contradicted" if an observation explicitly states the opposite;
- "unsupported" if nothing in the observations either confirms or refutes it.

Be strict: a claim that is plausible but not verifiable in the observations \
is "unsupported", not "supported". Answer only through the \
`submit_verdicts` tool.
"""

ASSERTIONS_JUDGE_SYSTEM_PROMPT = """\
You are an independent auditor. You are given raw OSINT tool observations \
(JSON), the final report written from those observations, and a list of \
expected assertions (some MUST appear in the report, others MUST NOT). For \
each assertion, say whether the report respects it ("respected"), violates \
it ("violated"), or whether it cannot be determined ("unclear"). Base your \
judgment on the report's CONTENT, not directly on the raw observations (the \
report may legitimately omit a detail present in the observations). Answer \
only through the `submit_verdicts` tool.
"""

_SUBMIT_VERDICTS_SPEC: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "submit_verdicts",
        "description": "Return one verdict per provided item, in the same order.",
        "parameters": {
            "type": "object",
            "properties": {
                "verdicts": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "verdict": {"type": "string"},
                            "justification": {"type": "string"},
                        },
                        "required": ["verdict", "justification"],
                    },
                }
            },
            "required": ["verdicts"],
        },
    },
}


@dataclass
class ClaimVerdict:
    claim: str
    verdict: Literal["supported", "unsupported", "contradicted", "judge_error"]
    justification: str


@dataclass
class AssertionVerdict:
    assertion: str
    expected: Literal["must_contain", "must_not_contain"]
    verdict: Literal["respected", "violated", "unclear", "judge_error"]
    justification: str


def summarize_verdicts(judge_results: dict[str, Any]) -> dict[str, Any]:
    """Aggregate the soft layer (Phase 2.2) across all domains: soft
    hallucination rate (unsupported/contradicted claims) and ground truth
    assertion compliance rate, each with the judge's own failure rate.

    The failure rate is computed and returned explicitly rather than
    absorbed into the denominator: a domain or claim in `judge_error` is
    neither a hallucination nor proof of reliability, it is a missing
    measurement (seen in Phase 2: 5/15 domains had a missing verdict,
    invisible until an aggregation existed — see
    evals/results/20260912_215745_RAPPORT.md §4)."""
    n_domains = len(judge_results)
    n_domain_errors = sum(1 for v in judge_results.values() if "error" in v)

    claim_verdicts = [
        c["verdict"]
        for v in judge_results.values()
        if "error" not in v
        for c in v.get("claims", [])
    ]
    assertion_verdicts = [
        a["verdict"]
        for v in judge_results.values()
        if "error" not in v
        for a in v.get("assertions", [])
    ]

    n_claims = len(claim_verdicts)
    judged_claims = [v for v in claim_verdicts if v != "judge_error"]
    hallucination_soft = (
        sum(1 for v in judged_claims if v in ("unsupported", "contradicted"))
        / len(judged_claims)
        if judged_claims
        else None
    )

    n_assertions = len(assertion_verdicts)
    judged_assertions = [v for v in assertion_verdicts if v != "judge_error"]
    assertions_respected = (
        sum(1 for v in judged_assertions if v == "respected") / len(judged_assertions)
        if judged_assertions
        else None
    )

    return {
        "n_domains": n_domains,
        "n_domain_errors": n_domain_errors,
        "domain_error_rate": (n_domain_errors / n_domains) if n_domains else None,
        "n_claims_judged": n_claims,
        "claim_judge_error_rate": (
            (n_claims - len(judged_claims)) / n_claims if n_claims else None
        ),
        "hallucination_soft": hallucination_soft,
        "n_assertions_judged": n_assertions,
        "assertion_judge_error_rate": (
            (n_assertions - len(judged_assertions)) / n_assertions if n_assertions else None
        ),
        "assertions_respected_rate": assertions_respected,
    }


def build_judge_provider(settings: Settings | None = None) -> LLMProvider:
    """Judge provider — ALWAYS DeepSeek (`deepseek-reasoner`), whatever the
    evaluated provider (`base.provider`). Two reasons, not one:
    1. never self-evaluate (a model judging its own report is structurally
       lenient);
    2. a CONSTANT judge on both sides of a DeepSeek/Mistral comparison is
       the only way to make soft hallucination scores comparable across
       providers — a judge that changes with the evaluated provider
       introduces a confounding variable, not just a bias.
    Therefore requires `DEEPSEEK_API_KEY` even when `base.provider == "mistral"`.
    Forces temperature=0 for reproducibility of the judgment itself, and its
    own timeout (see JUDGE_REQUEST_TIMEOUT) instead of the evaluated model's,
    which is too short."""
    base = settings or load_settings()
    judge_api_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    if not judge_api_key:
        raise ConfigError(
            "DEEPSEEK_API_KEY missing: required for the LLM judge (always "
            "DeepSeek, including when OSINTLLM_PROVIDER=mistral — see "
            "build_judge_provider)."
        )
    judge_settings = Settings(
        provider="deepseek",
        api_key=judge_api_key,
        base_url=os.getenv("DEEPSEEK_BASE_URL", DEEPSEEK_BASE_URL).strip(),
        model=JUDGE_MODEL_DEFAULT,
        temperature=None,  # deepseek-reasoner does not support temperature
        seed=base.seed,
        request_timeout=JUDGE_REQUEST_TIMEOUT,
    )
    return build_provider(judge_settings)


def _call_judge(
    provider: LLMProvider, system_prompt: str, user_content: str, n_items: int
) -> list[dict[str, str]]:
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content},
    ]
    last_error = ""
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            decision = provider.complete(
                messages=messages, tools=[_SUBMIT_VERDICTS_SPEC], tool_choice="auto"
            )
        except APITimeoutError as exc:
            last_error = f"Judge timeout (attempt {attempt}/{_MAX_RETRIES}): {exc}"
            continue

        call = _first_tool_call(decision.tool_calls, "submit_verdicts")
        if call is None:
            last_error = "The judge did not call submit_verdicts."
            continue
        verdicts = call.arguments.get("verdicts", [])
        if len(verdicts) != n_items:
            # The judge did not follow the requested 1:1 alignment — don't guess.
            last_error = "Number of verdicts != number of items."
            continue
        return verdicts

    return [{"verdict": "judge_error", "justification": last_error}] * n_items


def _first_tool_call(tool_calls: list[ToolCallRequest], name: str) -> ToolCallRequest | None:
    for c in tool_calls:
        if c.name == name:
            return c
    return None


# The agent's system prompt enforces "N. UPPERCASE TITLE" section headings
# (see agent.py:build_system_prompt), sometimes followed by a lowercase
# parenthesized group (e.g. "4. SUBDOMAINS (crt.sh)"). .isupper() alone
# misses that case (the whole line is no longer uppercase because of the
# parenthesis) — seen in Phase 2: these headings were judged "unsupported"
# as if they were factual claims.
_SECTION_TITLE_RE = re.compile(r"^\d+\.\s")


def _is_section_title(line: str) -> bool:
    if not _SECTION_TITLE_RE.match(line):
        return False
    core = _SECTION_TITLE_RE.sub("", line)
    core = re.sub(r"\([^)]*\)\s*$", "", core).strip()
    return bool(core) and core == core.upper()


def _extract_claims(report: OsintReport) -> list[str]:
    """Split the report's free text into discrete claims (one per non-empty
    sentence/bullet) for individual judging. Excludes section headings
    (numbered, uppercase): they are structural labels imposed by the system
    prompt, not factual claims."""
    parts: list[str] = []
    for raw_block in (report.summary or "").split("\n"):
        block = raw_block.strip(" -•*\t")
        if block and len(block) > 3 and not _is_section_title(block):
            parts.append(block)
    if report.risk_justification:
        parts.append(report.risk_justification.strip())
    parts.extend(r.strip() for r in report.recommendations if r.strip())
    return parts


def judge_report_claims(
    report: OsintReport, provider: LLMProvider | None = None
) -> list[ClaimVerdict]:
    provider = provider or build_judge_provider()
    claims = _extract_claims(report)
    if not claims:
        return []
    observations = json.dumps(report.collected, ensure_ascii=False, indent=2)
    user_content = (
        f"OBSERVATIONS (source of truth):\n```json\n{observations}\n```\n\n"
        "CLAIMS to judge, one per line:\n"
        + "\n".join(f"{i + 1}. {c}" for i, c in enumerate(claims))
    )
    verdicts = _call_judge(provider, CLAIMS_JUDGE_SYSTEM_PROMPT, user_content, len(claims))
    return [
        ClaimVerdict(
            claim=claim,
            verdict=v.get("verdict", "judge_error"),  # type: ignore[arg-type]
            justification=v.get("justification", ""),
        )
        for claim, v in zip(claims, verdicts)
    ]


def judge_assertions(
    report: OsintReport, gt: GroundTruth, provider: LLMProvider | None = None
) -> list[AssertionVerdict]:
    provider = provider or build_judge_provider()
    items: list[tuple[str, str]] = [(a, "must_contain") for a in gt.must_contain] + [
        (a, "must_not_contain") for a in gt.must_not_contain
    ]
    if not items:
        return []
    report_text = (
        f"SUMMARY: {report.summary}\n\nRISK JUSTIFICATION: {report.risk_justification}\n\n"
        f"RECOMMENDATIONS: {'; '.join(report.recommendations)}"
    )
    observations = json.dumps(report.collected, ensure_ascii=False, indent=2)
    user_content = (
        f"RAW OBSERVATIONS:\n```json\n{observations}\n```\n\n"
        f"REPORT TO AUDIT:\n{report_text}\n\n"
        "ASSERTIONS to judge, one per line (label must_contain = must appear, "
        "must_not_contain = must NOT appear):\n"
        + "\n".join(f"{i + 1}. [{kind}] {assertion}" for i, (assertion, kind) in enumerate(items))
    )
    verdicts = _call_judge(provider, ASSERTIONS_JUDGE_SYSTEM_PROMPT, user_content, len(items))
    return [
        AssertionVerdict(
            assertion=assertion,
            expected=kind,  # type: ignore[arg-type]
            verdict=v.get("verdict", "judge_error"),  # type: ignore[arg-type]
            justification=v.get("justification", ""),
        )
        for (assertion, kind), v in zip(items, verdicts)
    ]
