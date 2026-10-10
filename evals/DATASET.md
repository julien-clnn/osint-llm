# Evaluation dataset — 15 domains

> Phase 1.2 of the evaluation plan (see [docs/EVAL_PLAN.md](../docs/EVAL_PLAN.md)).
> Each domain was recorded in `--record` mode (**passive** reconnaissance,
> the default mode): the corresponding fixtures live in
> `evals/fixtures/<domain>/`, one per tool call actually made by the agent
> during recording. Replayable offline with `--replay`.

## Selection method

The domains aren't made up: every characteristic listed below was verified
with a direct lookup (WHOIS, DNS, crt.sh, IP geolocation + ASN) before
recording, not assumed up front. Two sensitive categories were chosen
explicitly:

- **Degraded reputation**: domain picked from the public
  [URLhaus](https://urlhaus.abuse.ch/) feed (abuse.ch), a recognized threat
  intel service, as of 2026-09-12. Passive lookups only (WHOIS, DNS,
  VirusTotal) — no interaction with the domain's content.
- **Government**: a French public-sector domain (`service-public.fr`),
  passive reconnaissance only.

All recordings were made in **passive** mode (`tech_fingerprint` not
invoked), consistent with the plan's rule of only showcasing this mode in the
public documentation.

## Composition

| # | Domain | Case demonstrated | Characteristic verified before recording |
|---|---|---|---|
| 1 | `microsoft.com` | Large organization, massive surface | 3698 subdomains in crt.sh |
| 2 | `github.com` | Large organization, intermediate scale | 117 subdomains in crt.sh — a useful contrast with #1 for the recall/precision metric (Phase 2) |
| 3 | `lemonde.fr` | Long Wayback history, French context | WHOIS domain from 2005, online media outlet since the mid-1990s |
| 4 | `service-public.fr` | Government domain | SPF present, **DMARC missing** — interesting in itself for an email posture audit of an institutional domain |
| 5 | `pets.com` | Domain with neither SPF nor DMARC | Confirmed by direct DNS lookup; MarkMonitor NS (brand protection registrar, defensive holding) |
| 6 | `theglobe.com` | Probably parked/inactive domain | Icon of the 2000 dot-com crash (IPO then bankruptcy); third-party NS (`giantpanda.com`, unrelated to the original company) suggesting a resale/parking |
| 7 | `discord.com` | Behind Cloudflare — misleading IP geolocation | Resolved IP → ASN **AS13335 Cloudflare, Inc.** confirmed (geolocation will point to a Cloudflare POP, not the real infrastructure) |
| 8 | `0rder-ver1f2345.com` | Degraded VirusTotal reputation | Active phishing domain, listed on URLhaus as of 2026-09-12 ("order verification" typosquat) |
| 9 | `aspenriver6.com` | Young WHOIS | Created on 2026-08-18 (< 1 month before recording); also listed on URLhaus — WHOIS freshness correlated with malicious activity is a realistic signal, not a dataset artifact |
| 10 | `qapilot.com` | Small organization, small surface | Young startup (recent launch), few subdomains/little infrastructure — not to be confused with a traditional "SME" in the administrative sense, but the same attack surface contrast |
| 11 | `craigslist.org` | Minimalist, self-hosted infrastructure | Own NS (`ns*.craigslist.org`), stable and atypical architecture — a good contrast baseline |
| 12 | `sourceforge.net` | Legacy platform | Old (1999), ~95 subdomains, good SPF/DMARC hygiene |
| 13 | `wikipedia.org` | Non-profit organization, global reach | Large-scale baseline outside the private sector |
| 14 | `cloudflare.com` | Security vendor | Deliberate contrast with #5 (`pets.com`) on the email posture hygiene expected from a security vendor |
| 15 | `abrush.ai` | Small, recent organization | WHOIS 2025-11 (~10 months), AI/creative sector |

## Reuse for the `phishing_triage` scenario (Phase 3)

Rather than recording a dedicated fixture set (extra network cost, not
needed), `phishing_triage` reuses this 15-domain set: its ground truth
already carries `reputation.verdict` (2 `malicious` —
`0rder-ver1f2345.com`, `aspenriver6.com` — and 13 `clean`), used by
`evals/harness/metrics.py:phishing_verdict_correct` to measure verdict
accuracy. See `evals/ground_truth/README.md`.

## What this dataset doesn't cover yet

- No **benign-but-similar** phishing domain (non-malicious typosquat), and no `suspicious` domain at all — `phishing_triage` accuracy can therefore only be measured on the malicious/benign contrast, not on the ambiguous cases that would best prove the scenario. To be completed with a dedicated labeled set if this measurement becomes a priority.
- The error injector (5 families, `evals/harness/injector.py`) and the LLM
  judge (`must_contain` assertions, `evals/harness/judge.py`) were only
  designed and tested for `external_recon` — they technically run for
  `email_security_posture`/`phishing_triage` (no crash), but their relevance
  for these scenarios hasn't been verified (Phase 3).
- `email_security_posture` pushes the LLM to make up candidate subdomain
  names (e.g. `mail.pets--pets.com`) instead of sticking to those from
  `enumerate_subdomains`, which causes non-reproducible fixture misses in
  `--replay` — details and causal hypothesis in `scenarios/README.md`
  ("Known limitation").
- The structured ground truth (`evals/ground_truth/<domain>.yaml`) isn't written yet: that's the purpose of Phase 2.1, once the metrics harness is in place.
- The "parked/inactive" status of `theglobe.com` and the exact nature of `pets.com` (defensive holding vs real activity) are inferred from indirect WHOIS/DNS signals, not from an active check of the content (consistent with passive mode) — to be noted as uncertainty if these domains are used as strict test cases in Phase 2.
