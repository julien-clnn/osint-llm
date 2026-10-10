# Changelog

Release history. Free-form (no versioned releases, single continuously
deployed project) — one entry per milestone. `D1`…`D10` = day 1…day 10.

- **D1** — project skeleton, DeepSeek key config, **WHOIS** tool wired into a
  minimal end-to-end agentic loop.
- **D2** — **crt.sh** (subdomain enumeration) and **IP geolocation**
  (ip-api.com) tools, with a shared HTTP client (User-Agent, throttling) and
  retries on the flaky crt.sh.
- **D3** — **multi-tool** loop + **structured report**: facts collected by the
  code, analysis (summary / risk / recommendations) provided by the LLM via a
  `submit_report` termination tool. JSON export + Markdown rendering. Tests
  (pytest).
- **D4** — **Streamlit** UI: live agent reasoning, **Folium map** of
  geolocated IPs, final report (color-coded risk, summary, recommendations,
  subdomains) and JSON download.
- **D5** — **multi-format export** of the report: JSON, Markdown and
  **styled standalone HTML** (printable to PDF). Download buttons in the UI,
  all 3 files written to `reports/` from the CLI.
- **D6** — guardrails: **disk cache** of tool results (errors are never
  cached), per-host HTTP throttling, multi-source fallback, clean error
  handling. Cache can be disabled (`--no-cache`, checkbox in the UI).
- **D7** — polish: `Makefile`, test domain list (`evals/test_targets.txt`), pinned Python
  (`.python-version`), MIT license, final README.
- **D8** — **React + FastAPI** web rewrite (SSE streaming), Streamlit
  archived (since removed).
- **D9** — extension: **ASN/IP ranges** (bgpview + RIPEstat) and **GitHub
  search** tools, plus a **multi-agent architecture** (verifier agent that
  audits the report before it is displayed).
- **D10** — 4 more tools: **DNS records** (MX/TXT/NS, SPF/DMARC), **Wayback
  Machine** (archive history), **tech fingerprint** (HTTP headers) and
  **VirusTotal** (reputation + passive DNS). The report gains *security
  posture*, *infrastructure history* and *reputation* sections, which the
  verifier agent reviews like everything else.
- **Phase 3 (evals)** — **declarative scenarios**: the agent's mission
  (exposed tools, system prompt, report structure) is now selected through a
  YAML file (`scenarios/`), without touching the loop code. Three scenarios:
  `external_recon` (default, original behavior), `email_security_posture` and
  `phishing_triage`.
- **Phase 4 (evals)** — **indirect prompt injection robustness**: adversarial
  suite of 10 cases / 6 families (`evals/adversarial/`), 4 measured
  mitigations (data/instruction separation, outbound domain allow-list,
  verifier injection pass, third-party text cap) — see
  [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
- **Phase 5 (eval UI)** — the eval harness can now be driven from the site:
  4-tab nav (Analysis, Benchmark, Results, Settings). **Benchmark** runs
  `evals/run_eval.py` live from the browser (domains/scenario/provider/
  repetitions, real cost estimate, explicit confirmation, live log, live
  architecture graph). **Results** shows a dashboard of past runs
  (with/without verifier, detection, LLM judgment, run-to-run comparison).
  **Settings** shows the active `.env` read-only.
