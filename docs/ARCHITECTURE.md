# Architecture

Technical overview of the project: the multi-agent pipeline, the repository
layout, declarative scenarios, and a walkthrough of the web UI. For the
"graph" description designed for automatic rendering (nodes/edges), see
[docs/AGENTS_GRAPH.md](AGENTS_GRAPH.md).

## Reconnaissance + verification

The project's key differentiator: the report is not shipped as-is by a single
LLM. **Two distinct agents** collaborate, with separate roles.

```
      domain
         │
         ▼
┌───────────────────────┐   calls the tools (WHOIS, subdomains,
│  RECONNAISSANCE agent │   geolocation, ASN, GitHub), archives the raw FACTS,
│  (agent.py, ReAct)    │   then writes the report via submit_report
└───────────┬───────────┘
            │ initial report + raw facts
            ▼
┌───────────────────────┐   checks EVERY claim in the report against the
│  VERIFIER agent       │   facts actually collected; flags hallucinations
│  (verifier.py)        │   or unjustified conclusions
└───────────┬───────────┘
            │  submit_verification
     verified?  ──── yes ──▶  verified report ✅ (shown to the user)
            │
            no (unsupported claims)
            ▼
     the orchestrator (investigation.py) sends the report back to the
     reconnaissance agent for CORRECTION from the same facts
     (revise_report — no new request, stays 100% passive),
     then re-verifies. Loop capped by OSINTLLM_MAX_VERIFY (default 2).
```

- **Separate roles**: the main agent *collects and synthesizes*; the verifier
  *audits* and has access to **no collection tool** — it only sees the raw
  facts + the report, which prevents it from introducing new data. Each has
  its own *system prompt* and its own termination tool (`submit_report` vs
  `submit_verification`).
- **Anti-hallucination**: since the facts are archived on the Python side,
  the verifier has a **source of truth** independent of the LLM's text. Any
  claim not supported by the data is flagged and then corrected.
- **Correction without new collection**: `revise_report` re-synthesizes from
  the facts **already** collected (`tool_choice` forced to `submit_report`) —
  so zero extra requests, and passivity is preserved.
- **Presentation**: the React UI shows both stages — a "Verified report /
  corrected after audit" banner, the list of unsupported claims and
  corrections, and the **initial report** (collapsible) when it was modified.

Measured (not assumed) impact of this second agent: [docs/RESULTS.md](RESULTS.md).

## MITRE ATT&CK layer (RAG)

Once the facts are collected, the reconnaissance agent sends its notable
findings to `attack_lookup` in one batched call. The tool retrieves the
matching ATT&CK techniques from a local index (hybrid BM25 + `mistral-embed`
retrieval, reciprocal rank fusion) and the agent maps findings to technique
IDs in the `attack_mappings` field of `submit_report`.

The verification step gains two checks: a deterministic one (any technique
ID that no `attack_lookup` call returned during the run fails the audit and
is sent back for correction; one that survives the correction rounds is
removed before display) and an LLM one (a justification contradicting the
retrieved excerpt is flagged). `OSINTLLM_ATTACK_RAG=0` turns the layer off
and restores the exact previous prompts and schemas.

Corpus, retrieval design, evaluation and limitations: [docs/RAG.md](RAG.md).

## Declarative scenarios

The reconnaissance agent (`agent.py`) runs a **mission** defined by a
declarative scenario — a YAML file in [`scenarios/`](../scenarios/) that
selects the tools exposed to the LLM, the system prompt and the expected
report structure, **without touching the agentic loop code**. The scenario is
chosen by the user (never by the LLM), alongside the Passive/Active mode:

| Scenario | Mission | Exposed tools |
|---|---|---|
| `external_recon` (default) | External attack surface mapping — the project's original behavior | all tools for the passive/active mode |
| `email_security_posture` | SPF/DMARC/DKIM audit, orphaned sending subdomains, certificate hygiene | `dns_records_lookup`, `enumerate_subdomains` |
| `phishing_triage` | Malicious/suspicious/benign verdict on a suspicious domain, from a set of weighted signals (WHOIS, reputation, passive DNS, Wayback) | `whois_lookup`, `virustotal_lookup`, `wayback_lookup` |

```bash
python main.py suspicious-domain.tld --scenario=phishing_triage   # CLI
curl "localhost:8000/api/analyze?domain=example.com&scenario=email_security_posture"  # API
```

In the UI, a dedicated selector appears next to Passive/Active. Details of
the YAML schema and of the choice to keep a single report schema (rather than
a dedicated output schema per scenario) in
[scenarios/README.md](../scenarios/README.md).

## Web UI — the 4 screens in detail

The site is a **React (Vite) app** with a "recon console" look, backed by a
**FastAPI API** that streams the agent's reasoning live (Server-Sent Events):
each tool call appears as it happens, then the final report (color-coded
risk, summary, IP map, subdomains, exports) is revealed in one go. In
production, `make build` compiles the frontend into `web/dist`, served by the
API itself — a single port.

- **Analysis** — domain form + Passive/Active mode + scenario + provider,
  live animated architecture graph (`AgentGraph`), final verified report.
- **Benchmark** — configures and runs `evals/run_eval.py` (`GET
  /api/eval/launch`, SSE) straight from the browser: domains, scenario,
  provider, repetitions/seed/workers, with an **honest cost estimate**
  (token/time averages from the last recorded run, never a made-up constant)
  and explicit confirmation before spending real LLM quota. One run at a time
  (server-side lock); the stream is read via `fetch()`+`ReadableStream`
  rather than `EventSource`, which automatically reconnects after any drop
  and would otherwise launch a whole duplicate run. During the run, a live
  architecture graph (`BenchmarkGraph`, the same visual building block as the
  Analysis screen) shows the recon agent, the verifier agent and the OSINT
  tools lighting up based on each task's real `AgentEvent`s — aggregated
  across up to `max_workers` concurrent tasks of the `ThreadPoolExecutor`
  (`--stream-events` on `run_eval.py`, relayed by `/api/eval/launch` as SSE
  `task` events), along with the list of active tasks (domain · config ·
  repetition · current tool). The two phases that follow `run_matrix` — the
  LLM judge (`judge.py`, always `deepseek-reasoner`) and the
  injector/detection (`injector.py` + `verifier.py`) — each have their own
  node, fed by the same start/end markers rather than full `AgentEvent`s
  (they are plain LLM calls, not a tool loop).
- **Results** — read-only dashboard of past runs (`GET
  /api/eval/runs[/{id}]`): with/without verifier comparison on the selected
  run (the harness's actual measurement axis), detection per injected error
  family, LLM-as-judge scoring, and a chart comparing the hallucination rate
  across all recorded runs.
- **Settings** — read-only view of the local `.env` (`GET /api/settings`):
  active provider, status of each known provider (key present or not),
  effective runtime parameters (temperature, seed, verification iterations,
  timeout). Nothing is ever written from the site.

**One-off provider choice** (Analysis and Benchmark screens) — a
DeepSeek/Mistral selector, preselected to the `.env`'s active provider,
forces that choice for **this** analysis or **this** run only
(`&provider=...`): never persisted, never written to `.env`
(`load_settings(provider=...)` in `config.py`, isolated to the subprocess
environment for an eval run).

## Repository layout

```
osintllm/
├── main.py                     # end-to-end test CLI
├── api.py                      # FastAPI API: SSE streaming, eval/settings routes, serves the React build
├── web/                        # React (Vite) frontend — main UI
│   ├── index.html
│   ├── vite.config.js          # /api → 8000 proxy
│   └── src/
│       ├── App.jsx             # 4-tab nav (Analysis/Benchmark/Results/Settings)
│       ├── screens/            # Analysis · Benchmark · Results · Settings
│       ├── components/         # ActivityStream · AgentGraph · BenchmarkGraph · ReportView · InfraMap
│       ├── lib/download.js     # client-side JSON/MD/HTML export (Blob)
│       └── styles.css          # "recon console" look
├── scenarios/                  # declarative scenarios (Phase 3) — see scenarios/README.md
│   ├── external_recon.yaml     # default scenario (original behavior)
│   ├── email_security_posture.yaml
│   └── phishing_triage.yaml
├── Makefile                    # install / run / api / web / serve shortcuts
├── requirements.txt
├── .env.example                # config template (copy to .env)
├── scripts/build_attack_index.py  # builds the MITRE ATT&CK index (make attack-index)
├── data/attack/                # committed ATT&CK v20.0 index (JSON + numpy)
├── tests/                      # pytest tests (mocked LLM, real tools)
└── src/osintllm/
    ├── config.py               # .env loading + settings (guardrails)
    ├── agent.py                # ReAct agentic loop + submit_report
    ├── report.py                # OsintReport (JSON / Markdown / HTML)
    ├── cache.py                 # disk cache of tool results
    ├── http.py                  # shared HTTP client (User-Agent, throttling)
    ├── verifier.py               # verifier agent (report audit)
    ├── investigation.py          # multi-agent orchestrator (recon + verification)
    ├── scenarios.py               # declarative scenario loading (scenarios/*.yaml)
    ├── rag/                       # ATT&CK retrieval: corpus, embeddings, index, BM25, retriever
    └── tools/
        ├── base.py                       # shared tool foundation
        ├── whois_tool.py                 # WHOIS tool (passive)
        ├── dns_records_tool.py           # DNS MX/TXT/NS + SPF/DMARC tool (dnspython)
        ├── crtsh_tool.py                 # subdomains via crt.sh tool (passive)
        ├── ipgeo_tool.py                 # IP geolocation via ip-api.com tool
        ├── asn_lookup_tool.py            # ASN / IP ranges tool (bgpview + RIPEstat, passive)
        ├── wayback_tool.py               # Wayback Machine history tool (CDX API)
        ├── tech_fingerprint_tool.py      # tech fingerprint via headers (1 request to target)
        ├── github_search_tool.py         # GitHub search tool (repositories + code)
        ├── virustotal_tool.py            # VirusTotal reputation + passive DNS tool
        ├── attack_lookup_tool.py         # MITRE ATT&CK lookup over the local index
        └── __init__.py                   # tool registry
```

Per-tool details: [docs/TOOLS.md](TOOLS.md).
