# Phase 2.4 log — context engineering iteration

> Goal of this phase: do an improvement pass on the format of the observations / history / system
> prompt, and measure the real before/after delta — no estimates, no made-up
> numbers. This file records every attempt, including the ones that don't
> work: that's what makes every number defensible rather than
> only showing the successes.
>
> The archived runs referenced here (`evals/results/`) were produced when the
> agent still reported in French.

## Attempt 1 — compact JSON in the verifier (2026-09-13)

**Starting observation**: `VerifierAgent.verify()` and `OsintAgent.revise_report()`
serialized `report.collected` to JSON with `indent=2` (pretty-print) before
sending it to the LLM. This text is never read by a human — indentation is
useless to an LLM and costs tokens in pure whitespace. Flagged as a serious
lead because both functions send the whole of `collected` on every call, and
the verification/correction cycle can run up to `max_verify_iterations=2`
times per run.

**Change tested**: `separators=(",", ":")` instead of `indent=2`, in
`verifier.py:125,134` and `agent.py:320` (revise_report). No information
lost, format only.

**Measurement** — the 2 most expensive domains in the baseline
(`service-public.fr`, `cloudflare.com`), 3 repetitions, DeepSeek, `--replay`:

| Domain | Config | Before (avg. of 3 reps, 09/12 baseline) | After (avg. of 3 reps) |
|---|---|---|---|
| service-public.fr | without verifier | 196,210 | 193,839 (≈ unchanged, expected) |
| service-public.fr | with verifier | 748,866 | 621,823 (**-17%**) |
| cloudflare.com | without verifier | 137,842 | 137,717 (≈ unchanged, expected) |
| cloudflare.com | with verifier | 347,690 | 509,194 (**+46%**) |

**Verdict: no net gain, change reverted.**

- "Without verifier" doesn't move, as expected (that path never calls the
  modified code) — confirms the change was properly scoped and that the
  measurement itself is reliable, not a measurement artifact.
- "With verifier" doesn't improve reliably: a net gain on
  service-public.fr, but a **46% increase on cloudflare.com**, reproducible
  across all 3 repetitions (509,268 / 508,594 / 509,719 — very little
  variance, so not noise).
- Most likely hypothesis, not formally confirmed: the real dominant cost
  driver isn't the size of each JSON call, it's **the number of correction
  rounds** (`verify` → `revise_report` → `verify`, up to 2 times). The
  baseline showed cloudflare.com corrected only 1 time out of 3
  repetitions; after this change, all 3 repetitions cost an almost identical
  and much higher amount — consistent with "all 3 repetitions now trigger a
  correction whereas only one did before", but **I didn't directly check the
  correction counter on this run**, so this remains a hypothesis to confirm,
  not an established fact.
- Compact JSON therefore wasn't the right lever: it acts on the size of one
  call, not on the number of calls, which appears to be the dominant factor.

**Code**: change reverted (back to `indent=2` in both files) — no trace in
`git diff` on `main`/the working branch; only the record of the attempt
remains, here and in the conversation history.

**Lead kept for the next attempt**: dig into why/how many times
`revise_report` is called per run (instrument the correction counter
directly, rather than inferring it from the total cost), before picking a
lever that targets the number of rounds rather than their individual weight.

## Instrumentation — correction counter (2026-09-13)

Added `InvestigationResult.correction_rounds` (an explicit counter of the
number of `revise_report` calls, propagated all the way to the summary table
— see commit `4793fa8`), to check Attempt 1's hypothesis without having to
infer it indirectly from the cost.

**Re-measurement on the ORIGINAL CODE (JSON fix already reverted)**, same 2
domains, 3 repetitions, with verifier:

| Domain | Repetition | Corrections | Tokens |
|---|---|---|---|
| service-public.fr | 1 | 1 | 749,267 |
| service-public.fr | 2 | 1 | 751,217 |
| service-public.fr | 3 | **0** | **377,898** |
| cloudflare.com | 1 | 1 | 516,154 |
| cloudflare.com | 2 | 1 | 517,146 |
| cloudflare.com | 3 | 1 | 517,291 |

**Two takeaways, and a correction to Attempt 1:**

1. **The hypothesis "the number of corrections dominates the cost" is
   unambiguously confirmed**: on service-public.fr, 0 corrections cost 378k
   tokens, 1 correction costs ~750k — almost exactly double. A correction
   amounts to paying for almost a whole run again.
2. **The 46% increase observed in Attempt 1 on cloudflare.com was NOT
   caused by the JSON fix.** Proof: here, with the ORIGINAL code (fix
   reverted), cloudflare.com triggers a correction on **3 repetitions out of
   3** — whereas the very first baseline (09/12) only had **1 out of 3**.
   Same code, same domain, different behavior from one run to the next. The
   LLM (`temperature=0` + fixed seed) is therefore not perfectly
   deterministic on the "should this report be corrected?" decision —
   Attempt 1 probably drew the wrong conclusion from an artifact of this
   variance, not from a real effect of the tested change.
3. **Methodological consequence**: comparing a before/after on 1 to 3
   repetitions per domain isn't reliable here, because the variable that
   weighs the most (correction triggered or not) varies on its own,
   independently of the modified code. A real context engineering test on
   this lever will require either more repetitions, or directly comparing the
   correction *rate* on a larger sample rather than the cost of 1-3 tries.

**Next lead, to discuss before coding**: rather than trying to reduce the
number of corrections (which depends on the verifier's judgment and is hard
to steer cleanly), reduce the **cost of a correction when it happens** —
`revise_report` sends the whole of `report.collected` as JSON every time,
even though the facts haven't changed between the initial report and its
revision; it's not obvious they need to be repeated in full.

## Attempt 2 — JSON format ruled out by measurement, real bug found (2026-09-13)

**Step 1, JSON format (isolated measurement, zero variance)**: to cleanly
settle Attempt 1's hypothesis without the noise from the number of
corrections, an isolated `verify()` call was made TWICE on the SAME report
(service-public.fr), once with `indent=2`, once compact — actual
`prompt_tokens`: 183,685 (indent) vs 182,191 (compact), i.e. **0.8%
savings**. DeepSeek's tokenizer already compresses repeated whitespace well:
the JSON format was never a significant lever. Lead definitively dropped, on
direct evidence this time (not on a full run muddied by correction
variance).

**Step 2, digging into the actual size of the collected facts**: on that
same service-public.fr report, `report.collected` weighed 617,558
characters, of which **589,926 (95%) were in a single key: `github_search`**.
Cause found: `_search_repositories()` (`github_search_tool.py`) never
truncated the repositories' `description` field, unlike `snippet` right next
to it (`_MAX_SNIPPET=300`, in place from the start) — an oversight. On this
real case, one repository had a **241,893-character** description (the
field abused for SEO/spam, a known and documented practice on GitHub).

**Fix** (commit `49fdaf2`): the same cap (300 characters) applied to
`description`. Since `--replay` fixtures freeze the tool result as recorded
(`Tool.run()` never re-executes the tool in replay mode, see `fixtures.py`),
the fix alone wouldn't have changed anything in the eval runs — the
already-recorded fixtures had to be re-truncated directly (same
transformation, no new network call, so as not to make the test set drift).
**7 fixtures out of 15 were affected**: `cloudflare.com`,
`craigslist.org`, `github.com`, `microsoft.com`, `pets.com`,
`service-public.fr`, `wikipedia.org` — exactly the domains that had
abnormally high costs in the 09/12 baseline, unexplained at the time (see
the detailed report, "notable points" section). 1,108,861 characters of
oversized descriptions removed in total.

**Measured result**: `service-public.fr` goes from 617,558 to 28,972
characters of collected facts (**-95%**) on a real `--replay` run. This is a
different kind of change from Attempt 1: it isn't context engineering
(format/prompt), it's a genuine missing-guardrail bug in an existing tool —
but with an effect far greater than anything a format tweak could bring.

**Measuring the real gain** — 7 domains, 2 configs, 1 repetition (14 runs),
total tokens vs the 09/12 baseline (average over 3 repetitions):

| Domain | Without verifier | With verifier |
|---|---|---|
| service-public.fr | -87% | -89% |
| cloudflare.com | -76% | -73% |
| pets.com | -47% | -76% |
| wikipedia.org | -65% | -53% |
| craigslist.org | -15% | -21% |
| github.com | ≈ 0% | ≈ 0% |
| microsoft.com | ≈ 0% | **+18%** |

**A big win on the targeted domains**, with two honest exceptions:
- `github.com`: almost unchanged — the affected content probably wasn't
  dominant there (a domain searching for repositories about itself).
- `microsoft.com` with verifier: **+18%**, counter-intuitive. Checked:
  `correction_rounds=1` on this single repetition, whereas the "before" was
  an average over 3 repetitions probably including cases without a
  correction — the same confusion as Attempt 1 (variance in the number of
  corrections, not an effect of the fix). Doesn't invalidate the overall
  result, but a reminder that a single repetition per domain remains fragile
  for `with_verifier` cases; to be rechecked with 3 repetitions if a
  definitive number is needed for microsoft.com specifically.

**Verdict**: unlike Attempt 1, this fix delivers a real, large and
consistent gain on most of the affected domains — the right lead wasn't the
message format, but a genuine unbounded-data bug in an existing tool.

## New official baseline — 8 domains, 3 repetitions (2026-09-13)

Full run (matrix + judge + injection) on a subset of **8 of the 15
domains** — chosen to maximize case diversity (large scale, Cloudflare,
malicious reputation, parked domain) and coverage of the domains affected by
the GitHub fix: `microsoft.com`, `service-public.fr`, `pets.com`,
`cloudflare.com`, `wikipedia.org`, `discord.com`, `0rder-ver1f2345.com`,
`theglobe.com`. 3 repetitions per configuration (hence reliable, unlike the
1-repetition measurements of the previous attempts).
Raw result: [evals/results/20260913_200113.json](results/20260913_200113.json).

| Metric | Before (09/12 baseline, these 8 domains) | After (GitHub fix) |
|---|---|---|
| Tokens/run, without verifier | 73,104 | 27,489 (**-62%**) |
| Tokens/run, with verifier | 218,380 | 67,949 (**-69%**) |
| Hard hallucination, without verifier | 0.52% | 0.0% |
| Hard hallucination, with verifier | 0.60% | 1.7% |

**The cost gain is clear and confirmed over 3 repetitions.** Hard
hallucination stays in the same order of magnitude (near zero on both sides)
— the fix doesn't degrade report reliability by trading cost for quality,
which would have invalidated the result.

**Caveat flagged, not hidden**: the verifier's false positive rate comes out
at 29% on this sample (vs 9.5% on the 15 domains of 09/12). Investigated:
`discord.com` and `cloudflare.com` trigger a verifier remark on an
already-correct report, reproducibly across all 3 repetitions, for reasons
unrelated to GitHub (TXT counts, IP range attribution, unsupported
interpretations). It's an effect of this small sample's composition (2
"touchy" domains out of only 8, vs being diluted across 15) — not a
regression introduced by the fix. Keep this in mind if the number is quoted
on its own: it isn't directly comparable to the 9.5% of the 15-domain
baseline without saying so.

## Phase 2.4 conclusion

Two attempts, a single gain kept, each recorded with its real numbers rather
than a single "success story":

1. **Compact JSON format** (Attempt 1/2): dropped. First believed to be
   positive on a 1-repetition run (tricked by the variance in the number of
   corrections), then measured directly on an isolated call (0.8% gain —
   negligible). DeepSeek's tokenizer already compresses repeated whitespace
   well.
2. **Missing cap on `github_search`**: kept. A genuine bug (not a prompt
   tweak) — an unbounded data field that could reach 241,893 characters on a
   real case. Gain confirmed over 3 repetitions: -62% to -69% tokens
   depending on the configuration, without degrading hallucination.

**The most useful methodological lesson of this phase**: the LLM isn't
perfectly deterministic on the "should this report be corrected?" decision,
even at `temperature=0`. Comparing a before/after on 1-3 repetitions per
domain is fragile as long as this variable isn't isolated — which is why
the correction counter instrumentation (`correction_rounds`, commit
`4793fa8`) remains useful beyond this phase, for any future measurement
involving the verifier.

**Lead explicitly set aside, not explored**: reducing the cost of a
correction by not sending the whole of `report.collected` on every
`revise_report` — riskier (potential information loss), and unnecessary once
the real bottleneck (the GitHub bug) was fixed, since the observation window
now stays reasonable (a few tens of KB instead of several hundred).
