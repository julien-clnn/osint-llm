# Evaluation plan

> **An entry point, not a rehash.** This document sets out what the evaluation
> aims to establish, the protocol that makes the numbers comparable, and what
> it doesn't cover. The details of each metric live in the docstring of the
> module that implements it (`evals/harness/`), as close to the code as
> possible — see the *Where things live* table at the bottom.

## Goal

The project doesn't aim to show that the agent "works". It aims to produce
defensible numbers on four questions:

1. **Does the agent make up facts?** — hallucination rate, measured in two
   layers (literal entities, then natural-language claims).
2. **Is the verifier agent any use?** — detection rate of injected errors,
   weighed against the **false positive rate** on correct reports. Without
   the latter, the former means nothing.
3. **At what cost?** — tokens, latency and tool calls per run, broken down by
   provider and configuration.
4. **What happens if a third-party source is hostile?** — indirect prompt
   injection suite (`evals/adversarial/`).

## Measurement protocol

### `--replay` mode only covers the tools

This is the most important point, and the easiest to misread: `--replay`
replays **tool results** from `evals/fixtures/<domain>/` — no network access
on the collection side. **The LLM provider, however, is really called.**

Direct consequences:

- A `make eval` spends real quota and budget, every time it runs.
- That's why [`.github/workflows/eval.yml`](../.github/workflows/eval.yml)
  is `workflow_dispatch` only, never on push or PR. Only the test CI
  ([`ci.yml`](../.github/workflows/ci.yml)) runs automatically, without a key.
- What replay neutralizes is **source drift** (WHOIS, crt.sh,
  VirusTotal…), not model variability.

### Determinism

The eval path forces its own settings (`runner.py:_settings_for_eval`):
`temperature=0` and a seed derived from the repetition (`seed + repetition`),
regardless of what's in `.env`. At `temperature=0`, residual variance remains
non-zero — it is measured, not assumed (see *What the evaluation doesn't
cover*).

### Repetitions and variance

Each configuration runs **3 times** per domain (`--repetitions`, default 3),
and every result is published as **mean ± standard deviation**. A comparison
between two models without a variance measurement is not admissible.

Two deliberate exceptions, for cost reasons: the **LLM judge** and **error
injection** only run once per domain, not on every repetition. They are
qualitative judgments that are expensive in calls; the variance we care
about is on the quantitative metrics (hard hallucination, completion, cost,
latency), which the full repetitions already cover.

### The judge is pinned

The LLM-as-judge **always runs on `deepseek-reasoner`**, regardless of the
provider under evaluation (`judge.py:build_judge_provider`) — a model never
judges itself, otherwise the DeepSeek/Mistral comparison would be biased.
The judge receives **only the run's tool observations** as authorized
context: neither the ground truth nor the evaluated agent's reasoning.

### Compared configurations

Two axes: `with_verifier` vs `without_verifier` (ablation of the verifier
agent), and one provider vs the other (DeepSeek vs Mistral). The numeric
results, their dates and their limitations are in
[docs/RESULTS.md](RESULTS.md).

## Re-running a measurement

```bash
make eval                                      # full suite: 15 domains x 3 repetitions
make eval-quick DOMAINS="qapilot.com"          # quick iteration, 1 repetition
make eval-scenario SCENARIO=phishing_triage DOMAINS="..."
make eval-adversarial                          # prompt injection suite
```

Outputs: `evals/results/<timestamp>.json` + a Markdown summary with the same
name (`evals/adversarial/results/` for the adversarial suite).

## Where things live

| Topic | Location |
|---|---|
| 15-domain set, selection method | [`evals/DATASET.md`](../evals/DATASET.md) |
| Ground truth schema | [`evals/ground_truth/README.md`](../evals/ground_truth/README.md) |
| Hallucination, hard layer (literal entities) | `evals/harness/entities.py` |
| Hallucination, soft layer + assertions (judge) | `evals/harness/judge.py` |
| Subdomain recall/precision, completion, orchestration | `evals/harness/metrics.py` |
| Injection of the 5 error families (verifier detection) | `evals/harness/injector.py` |
| Token/latency capture per LLM call | `evals/harness/runner.py` |
| Aggregation (mean, std dev, Markdown rendering) | `evals/harness/aggregate.py` |
| `make eval` orchestration | `evals/harness/cli.py` |
| Context engineering iteration, before/after deltas | [`evals/CONTEXT_ENGINEERING.md`](../evals/CONTEXT_ENGINEERING.md) |
| Attack surface and mitigations | [`docs/THREAT_MODEL.md`](THREAT_MODEL.md) |
| Numeric results and their limitations | [`docs/RESULTS.md`](RESULTS.md) |

## What the evaluation doesn't cover

Read this before quoting a number:

- **The fixtures are frozen.** Replay measures the agent's stability, not its
  robustness to drift or unavailability of the real sources.
- **The ground truth is derived from the recorded fixtures**, not from an
  independent source. Subdomain recall therefore measures the agent's
  faithfulness to what the tools actually returned — not the completeness of
  the collection itself.
- **3 repetitions don't make for statistical significance.** On some metrics
  (tokens per run with verifier), the standard deviation sometimes exceeds
  the mean: one or two outlier domains, not homogeneous behavior.
- **The judge is fallible, and it is measured as such.** The 2026-09-12
  DeepSeek baseline had 33% judge failures (5/15 domains without a verdict,
  due to timeouts); its soft-layer metrics rest on partial coverage. Details
  in [docs/RESULTS.md](RESULTS.md).
- **The verifier's false positive rate was measured on 8 domains**, not all
  15 — a deliberately contrasting subsample, so not representative in
  absolute terms.
- **Variance at `temperature=0` is real**: the number of corrections
  requested by the verifier varies from one repetition to the next on the
  same domain.
- **Recommendations are not sourced.** They come from the model's parametric
  memory, without being tied to a control framework — Phase 5 (RAG-based
  sourcing) hasn't been started. No metric therefore covers recommendation
  traceability.
- **Passive reconnaissance only.** Nothing measured here says anything about
  an active mode, which is out of the project's scope.
