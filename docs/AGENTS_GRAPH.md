# osintllm agents — description for graph rendering

> This document is intended for an AI tasked with producing a **graphical
> representation** (Mermaid, Graphviz, graph JSON, etc.) of the program. It
> describes each agent as a **node** with its inputs/outputs, and each
> interaction as an **edge**. Source of truth: [`src/osintllm/`](../src/osintllm/)
> for the runtime, [`evals/harness/`](../evals/harness/) for the judge. For the
> human-oriented narrative version, see
> [docs/ARCHITECTURE.md](ARCHITECTURE.md).

The program contains **two distinct graphs**, which must not be merged:

1. **RUNTIME graph** (production) — runs on every domain analysis, triggered
   by the CLI (`main.py`) or the API (`api.py`).
2. **EVALUATION graph** (offline) — runs only during eval campaigns
   (`evals/`), and **wraps** a run of the runtime graph as a sub-step before
   adding the judge.

---

## 1. RUNTIME graph (production)

### Nodes

| id | type | file | role | model/tool | has access to collection tools? |
|---|---|---|---|---|---|
| `orchestrator` | orchestrator (pure code, no LLM) | [`investigation.py`](../src/osintllm/investigation.py) `Investigator` | Chains recon → verification → bounded correction loop | — | no |
| `agent_recon` | LLM agent | [`agent.py`](../src/osintllm/agent.py) `OsintAgent` | ReAct loop: decides which tools to call, collects the facts, writes the report (`submit_report`) or corrects it (`revise_report`) | DeepSeek (`deepseek-chat`) or Mistral, depending on `OSINTLLM_PROVIDER` | yes (9 tools, see table below) |
| `agent_verifier` | LLM agent | [`verifier.py`](../src/osintllm/verifier.py) `VerifierAgent` | Audits the report against the raw facts, detects unsupported claims **and** prompt injections (`submit_verification`) | same provider as `agent_recon` | **no** — only sees the facts already collected, never a new tool |
| `tools` | group of passive/active tools | [`tools/`](../src/osintllm/tools/) | Collection of raw facts (real network I/O) | — (no LLM) | — |
| `scenario` | declarative config | [`scenarios/*.yaml`](../scenarios/) via [`scenarios.py`](../src/osintllm/scenarios.py) | Parameterizes `agent_recon`: mission, allowed tool subset, expected report sections | — | — |

Sub-nodes of `tools` (9), each with a `passive` flag (passive mode = no
direct contact with the target):

| tool | file | passive? |
|---|---|---|
| `whois_lookup` | [`whois_tool.py`](../src/osintllm/tools/whois_tool.py) | yes |
| `dns_records_lookup` | [`dns_records_tool.py`](../src/osintllm/tools/dns_records_tool.py) | yes |
| `enumerate_subdomains` (crt.sh) | [`crtsh_tool.py`](../src/osintllm/tools/crtsh_tool.py) | yes |
| `ip_geolocate` | [`ipgeo_tool.py`](../src/osintllm/tools/ipgeo_tool.py) | yes |
| `asn_lookup` | [`asn_lookup_tool.py`](../src/osintllm/tools/asn_lookup_tool.py) | yes |
| `wayback_lookup` | [`wayback_tool.py`](../src/osintllm/tools/wayback_tool.py) | yes |
| `github_search` | [`github_search_tool.py`](../src/osintllm/tools/github_search_tool.py) | yes |
| `virustotal_lookup` | [`virustotal_tool.py`](../src/osintllm/tools/virustotal_tool.py) | yes |
| `tech_fingerprint` | [`tech_fingerprint_tool.py`](../src/osintllm/tools/tech_fingerprint_tool.py) | **no** (contacts the target — active mode only, domain allow-list) |

### Edges (control and data flow)

```
domain + mode(passive|active) + scenario
        │
        ▼
   orchestrator ──calls Investigator.run()──▶ agent_recon.run(domain, mode, scenario)
        │
        │            agent_recon loops up to max_iterations:
        │              agent_recon ──LLM decision──▶ (tool_call | submit_report)
        │              tool_call ──dispatch──▶ tools.<name> ──raw result──▶ agent_recon
        │                                          (result archived as-is in `collected`)
        │
        ◀── initial_report (raw facts + LLM synthesis) ──
        │
        ▼
   orchestrator ──submit for audit──▶ agent_verifier.verify(report)
        │
        ◀── Verification{verified, unsupported_claims[], corrections[], injection_detected} ──
        │
        ├── verified=true AND injection_detected=false ─────▶ END: report shown to the user
        │
        └── otherwise (verified=false OR injection_detected=true), while
            correction_rounds < OSINTLLM_MAX_VERIFY (default 2):
                 orchestrator ──feedback (corrections+claims+injection alert)──▶
                     agent_recon.revise_report(report, feedback)
                     [no new tool call — re-synthesis on the SAME facts]
                 ◀── revised_report ──
                 └─▶ back to agent_verifier.verify() (new iteration)
```

Key structural points for the graph:
- `agent_recon` ←→ `tools` is an **N:N** loop (several tool calls per
  iteration, several iterations) bounded by `max_iterations` (from the
  scenario or `Settings.max_iterations`).
- `agent_recon` → `agent_verifier` → `agent_recon` is a correction loop
  bounded by `OSINTLLM_MAX_VERIFY` (default 2), **without** going back through
  `tools` (the `revise_report` edge has no edge to `tools`).
- `agent_verifier` has **no outgoing edge to `tools`** — this is the node's
  core security property (role isolation).
- `scenario` has an incoming edge to `agent_recon` only (parameterization),
  never to `agent_verifier`.

---

## 2. EVALUATION graph (offline, `evals/`)

This graph **contains an instance of the runtime graph** (via `OsintAgent`
alone, or the full `Investigator` depending on the run config) as a black
box, then adds a third agent: **the judge**.

### Nodes

| id | type | file | role | model | sees what |
|---|---|---|---|---|---|
| `eval_runner` | orchestrator (pure code) | [`evals/harness/runner.py`](../evals/harness/runner.py) | Runs N domains through `OsintAgent` or `Investigator` (depending on config) and collects the `record`s (report + facts) | — | — |
| `runtime_graph` | black box | (graph §1) | The system under test | DeepSeek or Mistral | everything (it does the collecting) |
| `judge` | LLM agent | [`evals/harness/judge.py`](../evals/harness/judge.py) | Audits the report *after the fact*, in 2 independent passes (see below) | **always** `deepseek-reasoner`, never the provider under evaluation | ONLY the raw facts (`report.collected`) + the report text — never the agent's reasoning, never the ground truth for pass 1 |
| `ground_truth` | static data | [`evals/ground_truth/*.yaml`](../evals/ground_truth/) | Expected assertions (`must_contain`/`must_not_contain`) per domain, written in advance by a human | — | — |
| `aggregator` | pure code | [`evals/harness/judge.py`](../evals/harness/judge.py) `summarize_verdicts` | Aggregates the judge's verdicts across all domains into rates (hallucination_soft, assertions_respected, the judge's own failure rate) | — | — |

The judge exposes two functions = two sub-passes, called from
[`evals/harness/cli.py:127-138`](../evals/harness/cli.py):

| pass | function | input | output | what it measures |
|---|---|---|---|---|
| 1. claim judgment | `judge_report_claims` | raw facts + claims extracted from the report (one per sentence/bullet) | verdict per claim: `supported` / `unsupported` / `contradicted` | "soft" hallucination (does the report say things not supported by the collected facts?) |
| 2. assertion judgment | `judge_assertions` | raw facts + full report + `ground_truth.must_contain/must_not_contain` | verdict per assertion: `respected` / `violated` / `unclear` | compliance with what a human expected for this domain |

### Edges

```
list of domains
        │
        ▼
   eval_runner ──for each domain──▶ runtime_graph (OsintAgent alone, or full Investigator)
        │
        ◀── record{report, collected, verifications?} ──
        │
        ▼
   eval_runner ──report.collected + extracted claims──▶ judge.judge_report_claims
        │                                                    │
        │                                              ◀── ClaimVerdict[] ──
        │
   eval_runner ──report.collected + report + ground_truth──▶ judge.judge_assertions
        │                                                          │
        │                                                    ◀── AssertionVerdict[] ──
        ▼
   aggregator ──across all domains──▶ aggregated metrics (evals/results/*.json|md)
```

Key structural points for the graph:
- `judge` has **no edge** to `runtime_graph` (`agent_recon`,
  `agent_verifier`, `tools`) — it never calls them, it only receives their
  output as input from `eval_runner`.
- `judge` is **always** pinned to `deepseek-reasoner`, including when
  `runtime_graph` runs with `OSINTLLM_PROVIDER=mistral` — a constant
  configuration edge, not a variable one like the edge to `runtime_graph`.
  Reason: avoid self-evaluation and keep the judge comparable across the
  providers under evaluation (see the `build_judge_provider` docstring).
- `ground_truth` only has an edge to `judge_assertions`, never to
  `judge_report_claims` (which must see ONLY the raw observations, never the
  ground truth, to remain an independent hallucination test).

---

## 3. Summary: who is an "agent" in the LLM sense?

Three LLM agents in total in the program, to be shown as "agent"-type nodes
in the graph (the other nodes — orchestrators, aggregator, tools, scenarios,
ground truth — are pure code/data, with no LLM call):

1. **`agent_recon`** (`OsintAgent`) — collection + synthesis, runtime.
2. **`agent_verifier`** (`VerifierAgent`) — internal audit, runtime, loops
   with `agent_recon`.
3. **`judge`** (`evals/harness/judge.py`) — external audit *after the fact*,
   offline only, never present in production, always DeepSeek.

`agent_verifier` and `judge` look alike (both audit a report against facts)
but **don't occupy the same place in the graph**: the former is in the
production loop and can trigger a correction before the report is shown to
the user; the latter is an external measuring instrument that never changes
anything, run only during eval campaigns.
