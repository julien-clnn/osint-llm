"""MITRE ATT&CK retrieval layer (RAG) — lets the agent ground its findings in
real ATT&CK techniques through the `attack_lookup` tool.

  - `corpus`: parses the official STIX 2.1 bundle into one document per
    technique, then into chunks (each chunk keeps the ID and the name);
  - `embeddings`: dense embeddings (`mistral-embed`) + an offline
    deterministic embedder for the tests, with a disk cache;
  - `index`: the local index on disk (JSON metadata + numpy array);
  - `bm25` / `retriever`: lexical, dense and hybrid (RRF) retrieval.

Design, evaluation and limitations: docs/RAG.md.
"""
