# Ground truth schema (Phase 2.1)

One `evals/ground_truth/<domain>.yaml` file per domain in the dataset
([evals/DATASET.md](../DATASET.md)). Every value is derived from the fixtures
actually recorded (`evals/fixtures/<domain>/`) — never made up.
`null` explicitly means "undetermined", not "false": the metric consuming the
field must handle the two cases differently (see `evals/harness/`).

```yaml
domain: example.com

subdomains:
  # Actual count returned by crt.sh (subdomain_count), not the list size
  # (often capped by the tool — see tools/crtsh_tool.py:_MAX_SUBDOMAINS).
  expected_count: 42
  # Sample of subdomains ACTUALLY observed in the fixtures, used for
  # recall/precision (Phase 2.2) — doesn't need to be exhaustive for domains
  # with a very large surface (e.g. microsoft.com, 3698 actual).
  known_sample:
    - www.example.com
  # Known noise subdomains from CT logs (usual certificate authority false
  # positives) to exclude from a precision penalty.
  known_exclusions: []

email_security:
  spf: true            # true | false | null (not verified / tool failed)
  dmarc: true
  dmarc_policy: reject  # reject | quarantine | none | null
  dkim_selectors_found: [selector1]   # heuristic detection, [] doesn't prove absence

network:
  expected_asn: 8075               # observed ASN (int), null if undetermined
  expected_org_substring: "Microsoft"  # expected substring in the resolved org/ISP
  behind_cdn_proxy: false          # true if the resolved IP belongs to a CDN/proxy
                                    # (Cloudflare, Fastly, Akamai...) -> IP geolocation
                                    # does NOT reflect the real infra (see must_not_contain)

reputation:
  verdict: clean        # clean | suspicious | malicious | unknown
  malicious_engines_min: 0   # min expected number of "malicious" VirusTotal engines

must_contain:            # 3 to 5 factual assertions the report MUST include
  - "..."

must_not_contain: []     # negative assertions (optional, e.g. misleading geolocation)

notes: >
  Free-form context: known uncertainties, peculiarities observed in the
  fixtures (e.g. two different IPs depending on the call, a transient tool
  failure that was re-recorded, etc.).
```

## Use by the metrics (Phase 2.2)

- **Subdomain recall/precision**: compares `report.subdomains()` to
  `subdomains.known_sample` (recall) and flags any entry outside
  `known_sample ∪ known_exclusions` as potential imprecision — to be
  interpreted with caution on domains with a very large surface, where
  `known_sample` is deliberately partial.
- **Hallucination (hard layer)**: the entities in the `network`/`email_security`
  fields serve as a human reference, but the automatic check compares the
  report to the **fixtures**, not to the ground truth (see `evals/harness/hallucination.py`).
- **Orchestration efficiency**: a non-null `email_security`/`network` signals
  that a check (DMARC, ASN...) was possible — a run that doesn't call the
  corresponding tool counts as a missed call.
- **Assertions**: `must_contain`/`must_not_contain` are checked by the LLM
  judge (soft layer), with the tool observations as the only authorized
  context.
- **Verdict accuracy (`phishing_triage`, Phase 3)**: `reputation.verdict`
  also serves as ground truth for this scenario — see
  `evals/harness/metrics.py:phishing_verdict_correct`, which compares the
  report's `risk_level` (translated into a verdict via
  `scenarios/phishing_triage.yaml:risk_level_mapping`) to `malicious`/`clean`.
  The current dataset only covers these two verdicts (no `suspicious` domain
  so far) — see `evals/DATASET.md`.
