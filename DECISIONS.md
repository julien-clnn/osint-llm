# Architecture decisions

A record of the structural choices and the reasoning behind them, as of now.
See also [CHANGELOG.md](CHANGELOG.md) for the release timeline.

- **MITRE ATT&CK grounding through retrieval, with a hand-written hybrid
  retriever.** Okapi BM25 (~40 lines) + dense `mistral-embed` vectors, fused
  by reciprocal rank fusion; the index is plain files (`data/attack/`, JSON +
  a numpy matrix) loaded in memory: ~1,800 chunks need neither a vector
  database server nor a RAG framework. Hybrid because each method fails where
  the other succeeds (measured in [docs/RAG.md](docs/RAG.md)). One new
  dependency, **`numpy`** (embedding matrix + cosine similarity). Embeddings
  come from Mistral whatever
  the chat provider: DeepSeek exposes no embedding model.
- **ATT&CK IDs are checked deterministically.** "Zero invented technique ID"
  is enforced by code (regex over the report vs IDs returned by
  `attack_lookup` during the run), which turns the target into a guarantee;
  the LLM verifier only judges whether a justification fits the retrieved
  text.
- **The last step of the agent loop forces the report.** Measured with
  `mistral-small`, which calls one tool per step: without it, a third of the
  runs ended on the iteration cap with no report at all. The forced report
  uses only the facts already collected and is marked `report_forced`, so
  the eval still tells it apart from a spontaneous one.
- **`attack_lookup` bypasses the replay fixtures.** Its argument is free
  text written by the LLM and changes from run to run, so a fixture keyed on
  exact arguments could never match; its result is already deterministic
  (local index, cached query embeddings).
- **Two separate agents (reconnaissance + verification), not a single LLM.**
  The verifier audits the report against facts archived on the Python side and
  has access to **no collection tool** — it cannot introduce new data, only
  judge what already exists. Details in
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Measured (not assumed) impact
  in [docs/RESULTS.md](docs/RESULTS.md).
- **The evaluation judge is pinned to `deepseek-reasoner`**, regardless of the
  provider under evaluation (`evals/harness/judge.py:build_judge_provider`) — a
  model never judges itself, otherwise the DeepSeek/Mistral comparison would be
  biased.
- **No agent framework** (LangChain & co): the ReAct loop is hand-written in
  `src/osintllm/agent.py`, to keep control over and visibility into exactly
  what each LLM call sees — required for the anti-injection audit (see
  [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)).
- **Facts vs analysis**: raw tool data is collected and attached to the report
  by the code (trustworthy); the LLM only provides the analysis, via the
  `submit_report` tool whose schema enforces the structure (no brittle
  parsing, risk constrained to an enum).
- **Declarative scenarios (YAML) rather than one output schema per mission**:
  a single report schema, parameterized per scenario (exposed tools, prompt,
  expected sections) — see [scenarios/README.md](scenarios/README.md) for the
  rationale.
- **DeepSeek via the `openai` SDK**: the DeepSeek API is compatible with OpenAI
  function calling, so we reuse the official client and only change
  `base_url`. Mistral follows the same path (see
  [docs/CONFIGURATION.md](docs/CONFIGURATION.md)).
- **Branching: topic branch → `develop` → `main`.** Every PR targets
  `develop`; `main` only receives release merges from `develop`.
- **WHOIS via `python-whois`** (socket queries) rather than the system binary,
  for a self-contained, portable project.
- **Python 3.12 via `uv`**: Python 3.14 (the only version on the machine) did
  not yet have reliable wheels for Streamlit/Folium (the first UI).
- **React + FastAPI (SSE) rather than Streamlit** for the main UI (D8, see CHANGELOG): live
  streaming of the agent's reasoning, fine-grained control over rendering
  (animated architecture graph, eval dashboard) — Streamlit reruns the script
  on every interaction, which is a poor fit for a long-running stream. See
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). The Streamlit UI was later
  removed entirely (dead code, heavy dependencies).
