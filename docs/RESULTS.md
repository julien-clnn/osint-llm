# Evaluation results

> Work in progress (`evals/`, see [evals/CONTEXT_ENGINEERING.md](../evals/CONTEXT_ENGINEERING.md)
> for the details of each attempt, including the ones that didn't work).
> Real numbers, produced by `make eval` in `--replay` mode — never estimated.
> **Evaluation methodology, protocol and limitations:
> [docs/EVAL_PLAN.md](EVAL_PLAN.md).**
>
> The archived runs in `evals/results/` (and `evals/adversarial/results/`)
> were produced when the agent still wrote its reports in French: quoted
> report values such as `risk_level='moyen'` (medium) or `'faible'` (low)
> reflect that (current values are `low`/`medium`/`high`/`undetermined`;
> the legacy French values are still accepted when reading archived results).

## DeepSeek vs Mistral comparison (15 domains, 2026-09-15)

15 domains from the full eval set, 3 repetitions per configuration,
`temperature=0`. The LLM-as-judge always runs on `deepseek-reasoner` for both
providers — never the model under evaluation judging itself (see
[Architecture decisions](../DECISIONS.md)).

`deepseek-chat` on the DeepSeek side. On the Mistral side,
**`mistral-small-2603`** — deliberately not their most capable model:
`mistral-large-latest` is capped at 15 req/min on this account (measured via
the `x-ratelimit-*` headers), which makes a run of this size impractical
without running it serially for hours; `mistral-medium-latest` handles the
throughput (1000 req/min) but costs 3 to 10x more per token than `large` and
`small`. **This comparison therefore pits DeepSeek's flagship model against a
budget Mistral model, not two models of the same tier** — keep this in mind
when reading the numbers below.

| Metric | DeepSeek — no verifier | Mistral — no verifier | DeepSeek — with verifier | Mistral — with verifier |
|---|---|---|---|---|
| Successful runs | 45/45 | 45/45 | 45/45 | 45/45 |
| Completion rate | 100% | **33%** | 100% | 100% |
| Hard hallucination | 0.012 ± 0.040 | 0.162 ± 0.170 | 0.003 ± 0.021 | 0.044 ± 0.067 |
| Subdomain recall / precision | 1.00 / 0.50 ± 0.47 | 1.00 / 0.50 ± 0.47 | 1.00 / 0.50 ± 0.47 | 1.00 / 0.50 ± 0.47 |
| Tokens per run | 49,560 ± 51,775 | 39,835 ± 15,338 | 138,592 ± 190,344 | 79,048 ± 36,127 |
| Latency per run | 10.8s ± 0.9 | 8.4s ± 7.6 | 22.2s ± 7.9 | 23.4s ± 8.3 |
| Corrections per run | — | — | not instrumented on this run | 0.87 ± 0.34 |

**The clearest result: without the verifier, Mistral small only finishes
cleanly 1 time out of 3** (30/45 runs stuck at `max_iterations`, never
calling `submit_report`; 15/45 finished). DeepSeek finishes 100% of the time
in both configurations. With the verifier, Mistral catches up on completion
(100%) but at the cost of many more corrections (39/45 reports corrected vs
28/45 for DeepSeek). **For DeepSeek, the verifier is a quality refinement
(hard hallucination 0.012 → 0.003); for Mistral small, it's what makes the
agent usable at all.** This is the most telling ablation test in the eval
plan: the value of the multi-agent architecture depends heavily on the
underlying model — it isn't a uniform "bonus".

**Verifier detection**: 100% detection across the 5 injected error families,
on both sides. False positive rate (intact report wrongly flagged): **9.5%
for DeepSeek, 0.0% for Mistral** on this sample.

**Actual measured cost** — main Mistral matrix (90 runs, 5.2M prompt tokens
+ 151k completion tokens): **~€0.87** at the `mistral-small-2603` rate
($0.15 / $0.60 per M tokens in/out). DeepSeek cost not given in euros in
this comparison: DeepSeek's current pricing page no longer lists
`deepseek-chat` under that exact identifier (the lineup has since been
renamed), and rates also vary by time of day — better not to show an
unverified figure than to estimate one.

**Known limitations of this comparison**:
- The 15-domain DeepSeek baseline dates from 2026-09-12 and had **33% judge
  failures on the LLM judge side (5/15 domains without a verdict, timeout)**
  — its "soft layer" metrics (soft hallucination, assertions respected) rest
  on partial coverage, unlike the Mistral run (0/15 failures, full
  coverage). Not comparable at the same confidence level on that specific
  part.
- Model tier asymmetry (see above): `deepseek-chat` vs
  `mistral-small-2603`, not two flagships.
- 3 repetitions per case: reduces uncertainty without eliminating it,
  especially on high-variance metrics (tokens/run with verifier, where the
  standard deviation sometimes exceeds the mean on the DeepSeek side — a sign
  of one or two outlier domains, not of homogeneous behavior).

## 2026-09-13 baseline

8 of the 15 domains in the eval set (`microsoft.com`, `service-public.fr`,
`pets.com`, `cloudflare.com`, `wikipedia.org`, `discord.com`,
`0rder-ver1f2345.com`, `theglobe.com` — a selection covering the most
contrasting cases: large scale, Cloudflare, malicious reputation, parked
domain), DeepSeek (`deepseek-chat`), `temperature=0`, 3 repetitions per
configuration.

| Metric | Without verifier | With verifier |
|---|---|---|
| Successful runs | 24/24 (0% error) | 24/24 (0% error) |
| Completion rate | 100% | 100% |
| Hard hallucination (unsupported entities) | 0.0% | 1.7% |
| Subdomain recall / precision (vs known sample) | 1.00 / 0.53 | 1.00 / 0.53 |
| Tokens per run | 27,489 ± 4,982 | 67,949 ± 17,568 |
| Latency per run | 11.1s ± 1.0 | 24.1s ± 6.0 |
| Corrections per run | — | 0.79 ± 0.41 |

**Verifier detection** (5 injected error families): 100% detection across
the 5 families, with a false positive rate of 29% on this subsample (2 of the
8 domains — `discord.com`, `cloudflare.com` — trigger verifier remarks on
reports that are already correct, reproducibly across all 3 repetitions; an
effect of this small sample's composition, not a measured regression).

**Before/after delta (Phase 2.4, context engineering)**: on these same 8
domains, a fix cut token cost by **62% (without verifier) to 69% (with
verifier)**, without degrading the hallucination rate. This isn't a prompt
tweak: `github_search_tool.py` returned GitHub repository descriptions with
no size limit at all (up to 241,893 characters observed on a real case,
versus a 300-character cap already in place for code snippets right next to
it) — a genuine missing-guardrail bug, not fine-tuning. An initial approach
(compacting the JSON sent to the verifier) was tested and dropped: 0.8% gain
measured on an isolated call, negligible. Full details of both attempts in
[evals/CONTEXT_ENGINEERING.md](../evals/CONTEXT_ENGINEERING.md).

**Known limitations**: this baseline only covers 8 of the 15 domains in the
full set (real cost constraints) — see the 15-domain run with the Mistral
comparison above, which supersedes this subset for any overall reading; the
number of corrections requested by the verifier varies noticeably from one
repetition to the next for the same domain, even at `temperature=0` — a
source of noise to keep in mind for any comparison based on few repetitions.

## Adversarial robustness (Phase 4)

> Full details — attack surface, method, raw results — in
> [docs/THREAT_MODEL.md](THREAT_MODEL.md). Numbers produced by
> `make eval-adversarial` (DeepSeek, `temperature=0`, 10 cases / 6 families).

osintllm ingests content controlled by the domain it analyzes (WHOIS, DNS,
GitHub, Wayback…): an attacker can plant instructions there designed to
manipulate the report. Four mitigations are in place: delimited
data/instruction separation in the prompt, a domain allow-list for the only
tool that contacts the target (`tech_fingerprint`), a verifier pass
dedicated to injection detection, and a cap on third-party text.

There is no clean "no mitigation" baseline (the first two attempts failed
due to DeepSeek API instability, before producing any result). The first
usable measurement, once the mitigations were in place, had a methodological
bias (3 cases tested on domains that were already legitimately "low", 2
cases not measurable for lack of a fixture) — fixed, then re-measured:

| Family | 1st measurement (biased) | After method fix |
|---|---|---|
| direct_instruction | 0%¹ | 50%² → 0%³ |
| exfiltration | not measurable | 0% |
| fake_tool_result | 100%¹ | 0% |
| fake_system_message | 100%¹ | 0% |
| authority_claim | 100%¹ | 0% |
| verifier_manipulation | 0% | 0% |

¹ Domains whose ground truth was already "low" — the rate doesn't prove the
injection worked. ² Only one of the 2 cases (`direct_instruction_dns_txt`)
succeeds, on a single repetition; it produced a different verdict from one
run to the next with the same payload and the same seed — native API
variance at `temperature=0`, not a confirmed mitigation failure.
³ Reconfirmed on 2026-09-19 with 3 repetitions on this specific case:
`risk_level='moyen'` (medium) held every time, never 'faible' (low) — the
isolated "success" was indeed API noise, not a breach.

**Residual rate**: **0 cases out of 10** — all 6 families are consistently
blocked, including `direct_instruction` once API variance is ruled out by
repetition.
