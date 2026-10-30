# Available tools

| Tool                    | Third-party source         | Returns                                       |
|-------------------------|----------------------------|-----------------------------------------------|
| `whois_lookup`          | WHOIS registries           | registrar, dates, name servers, registrant    |
| `dns_records_lookup`    | DNS resolver               | MX, TXT, NS + **email posture** (SPF/DMARC)   |
| `enumerate_subdomains`  | crt.sh (CT logs)           | list of known subdomains                      |
| `ip_geolocate`          | ip-api.com                 | country, city, coordinates, ISP (AS)          |
| `asn_lookup`            | bgpview.io + RIPEstat      | the organization's ASN + **all its IP ranges** |
| `wayback_lookup`        | web.archive.org (CDX)      | **historically archived** subdomains/URLs     |
| `tech_fingerprint`      | the target (1 request)     | tech stack + **header hardening**             |
| `github_search`         | api.github.com (Search)    | related repositories + exposed code (potential secrets) |
| `virustotal_lookup`     | VirusTotal (API v3)        | **reputation** + passive DNS (associated IPs) |
| `attack_lookup`         | local MITRE ATT&CK index   | **ATT&CK techniques** matching the findings (see [RAG.md](RAG.md)) |

## A closer look at the tools that broaden the reconnaissance

- **`asn_lookup(ip)`** starts from an IP and traces it back to the **ASN**
  (autonomous system) of the organization announcing it, then lists **all the
  CIDR prefixes** registered to that ASN — the real network footprint, not
  just a single point. The report and the "Network map (ASN)" section of the
  UI present these ranges.
- **`github_search(domain)`** searches GitHub for public repositories and
  code mentioning the domain: repositories tied to the organization, and above
  all **secrets / API keys / configs committed by mistake**. Repository search
  works without authentication; **code** search requires a `GITHUB_TOKEN`
  (otherwise it is cleanly disabled and reported as such).
- **`dns_records_lookup(domain)`** fetches MX/TXT/NS and derives the **email
  posture** from them: presence of SPF (`v=spf1`), DMARC (`_dmarc`, with its
  `p=` policy) and DKIM hints. Missing SPF/DMARC = domain exposed to
  spoofing.
- **`wayback_lookup(domain)`** queries the **Wayback Machine** (CDX API) to
  list historically archived infrastructure: forgotten subdomains, notable old
  URLs (`admin`, `backup`, `.git`, `.env`…) and the date range covered.
- **`tech_fingerprint(domain)`** infers the stack (Server, X-Powered-By,
  cookies) and the **security header hardening** (CSP, HSTS,
  X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
  Permissions-Policy) → `n/6` score.
- **`virustotal_lookup(domain)`** returns the **reputation** (aggregated
  engine verdicts, votes, categories) and **passive DNS** (historically
  associated IPs). Requires `VT_API_KEY`; without a key, it disables itself
  cleanly. Low free quota (~4 req/min, 500/day): the disk cache avoids
  burning it again.

## A caveat on passivity

Collection only queries public third parties — **except**
`tech_fingerprint`, which sends **a single lightweight HTTP GET request**
(headers only, no crawling) to the target's home page. It's the smallest
possible footprint, openly acknowledged as such, at the edge of "passive".
Also, `dns_records_lookup` (like geolocation) involves **DNS resolution**,
which may ultimately hit the target's authoritative name servers — the usual
limit of "passive" OSINT.
