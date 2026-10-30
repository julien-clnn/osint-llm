# ATT&CK retrieval eval

Measures how well `attack_lookup` retrieves the right MITRE ATT&CK technique
for a real finding — BM25 only, dense only, hybrid. Method, results and
limitations: [docs/RAG.md](../../docs/RAG.md).

| Step | Command | API calls |
|---|---|---|
| 1. Extract the findings from `evals/fixtures/` | `python evals/rag/extract_observations.py` | none |
| 2a. Label with DeepSeek | `python evals/rag/label_with_deepseek.py` | `deepseek-v4-pro` |
| 2b. Label with an independent Claude agent | manual, guideline in `labeling.py` | — |
| 3. Merge into the gold set (intersection) | `python evals/rag/build_gold.py` | none |
| 4. Run the retrieval eval | `make eval-rag` (offline replay) or `python evals/rag/run_retrieval_eval.py` | `mistral-embed`, first run only |
| Agent-level overhead | `make eval-rag-agent`, then `python evals/rag/compare_agent_runs.py <off>.json <on>.json` | real LLM calls |

Committed artifacts: `observations.json`, `labels/`, `gold.json`,
`embedding_cache/` (query embeddings, so step 4 replays offline) and
`results/`.
