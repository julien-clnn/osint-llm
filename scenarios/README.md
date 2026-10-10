# Declarative scenarios (Phase 3)

A scenario selects the agent's **mission** — without touching the agentic
loop code (`src/osintllm/agent.py`). Loaded by `src/osintllm/scenarios.py`,
selected by the user (CLI `--scenario`, API `?scenario=`, selector in the
UI) — never by the LLM itself.

```yaml
name: my_scenario           # must match the file name
label: "Display name"       # UI, exports, API payload

# Paragraph injected into the system prompt (see agent.py:build_system_prompt),
# replacing the default scenario's "tools to use / signals to exploit" clause.
# `{fingerprint_clause}` is only useful to external_recon (the only scenario
# whose clause varies with passive/active mode) — other scenarios can omit it.
mission: >-
  Free-form text describing the mission's goal and how to interpret the
  tools' results.

tools: null                 # null = all tools for the passive/active mode;
                             # otherwise a list of names (see src/osintllm/tools/__init__.py)
  # - dns_records_lookup
  # - enumerate_subdomains

report_sections:             # headings illustrating the expected structure of
  - "SECTION HEADING 1"      # the `summary` field (see submit_report); only
  - "SECTION HEADING 2"      # the first 2 are shown to the LLM as an example

risk_level_mapping: null    # or {high: ..., medium: ..., low: ..., undetermined: ...}
                             # — see "Why no dedicated schema" below

max_iterations: null        # null = inherits Settings.max_iterations
```

## Why no dedicated output schema per scenario

`email_security_posture` and `phishing_triage` produce fairly different
things (an email security posture, a malicious / suspicious / benign
verdict). Option considered then dropped: letting each scenario declare its
own output structure (fields, enums). Chosen instead: all three scenarios
reuse **the same** `submit_report` **schema** (`summary`, `risk_level` ∈
{low, medium, high, undetermined}, `risk_justification`,
`recommendations`). The legacy French values (`faible`, `moyen`, `élevé`,
`indéterminé`) found in archived runs are still accepted when reading them.

For `phishing_triage`, `risk_level_mapping` tells the LLM how to use
`risk_level` as a **verdict** (high→malicious, medium→suspicious,
low→benign, undetermined→undetermined); the detailed reasoning (set of
signals, weighting) goes into `risk_justification`. This field is also used by `api.py` (computing
`verdict_label` for display) and by
`evals/harness/metrics.py:phishing_verdict_correct` (verdict accuracy
against the ground truth).

Deliberate trade-off: zero changes to `report.py` (Markdown/HTML rendering),
the API, the React frontend or the existing eval metrics — at the cost of a
slightly less natural display ("Risk: HIGH" rather than "Verdict: MALICIOUS"
in the raw schema; the UI translates via `verdict_label` when this mapping
exists).

## Available scenarios

| File | Mission | Exposed tools |
|---|---|---|
| `external_recon.yaml` | External attack surface mapping (original behavior, default) | all tools for the passive/active mode |
| `email_security_posture.yaml` | SPF/DMARC/DKIM audit, sending subdomains, certificate hygiene | `dns_records_lookup`, `enumerate_subdomains` |
| `phishing_triage.yaml` | Malicious/suspicious/benign verdict on a suspicious domain, weighted signals | `whois_lookup`, `virustotal_lookup`, `wayback_lookup` |

Known limitation: the optional "typosquat similarity"
parameter planned for `phishing_triage` is not implemented.

## Known limitation — `email_security_posture` and `--replay` mode

Observed during a smoke test (1 domain, 1 repetition, `pets.com`,
2026-09-13): the `email_security_posture` mission asks the LLM to spot
"orphaned sending subdomains (e.g. mail.\*, smtp.\*...)", which pushes it to
**make up candidate subdomain names** to test via `dns_records_lookup`,
instead of sticking to those actually returned by `enumerate_subdomains`.
Observed over 3 successive attempts: `_dmarc.pets.com`,
`mail.pets--pets.com`, then `pets--pets.com` — three different names, the
last of which doesn't match anything plausible.

Practical consequence: in `--replay`, each new attempt can miss a different
fixture (the LLM isn't deterministic about *which* names it makes up, even
at `temperature=0` — same lesson as Phase 2.4). Two fixtures were recorded by
hand for `pets.com` after this smoke test
(`evals/fixtures/pets.com/dns_records_lookup__a452abf58e71.json` and
`__ab236a7999dd.json`, real results — one rejected by the tool's validation,
the other an empty DNS response), but nothing guarantees a future run will
converge: this isn't a one-off missing fixture, it's exploratory behavior of
the scenario itself.

**Not fixed in this PR** (an explicit decision, not an oversight): the most
likely fix — rewording the mission to say explicitly to only check the
subdomains returned by `enumerate_subdomains`, never to make any up — hasn't
been tested, so as not to reopen the already-reviewed content of
`email_security_posture.yaml` without a dedicated isolated measurement (see
the method in `evals/CONTEXT_ENGINEERING.md`, Phase 2.4). To be revisited in
a dedicated iteration if this scenario needs an in-depth evaluation.
