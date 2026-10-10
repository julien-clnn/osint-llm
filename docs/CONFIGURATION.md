# Configuration

The exhaustive, up-to-date reference, commented variable by variable, is
[`.env.example`](../.env.example) — copy it to `.env` (never committed).
This document provides the narrative context the inline comments don't have
room for.

## Overview

| Variable            | Default                     | Purpose                       |
|----------------------|------------------------------|---------------------------------|
| `OSINTLLM_PROVIDER`  | `deepseek`                   | active provider: `deepseek` \| `mistral` |
| `DEEPSEEK_API_KEY`   | — (**required if provider=deepseek**) | DeepSeek API key   |
| `DEEPSEEK_BASE_URL`  | `https://api.deepseek.com`   | API endpoint                  |
| `DEEPSEEK_MODEL`     | `deepseek-chat`               | model used                    |
| `MISTRAL_API_KEY`    | — (**required if provider=mistral**) | Mistral API key      |
| `MISTRAL_BASE_URL`   | `https://api.mistral.ai/v1`   | API endpoint                  |
| `MISTRAL_MODEL`      | `mistral-large-latest`        | model used                    |
| `GITHUB_TOKEN`       | — (optional)                   | enables GitHub code search + higher quota |
| `VT_API_KEY`         | — (optional)                   | enables `virustotal_lookup` (reputation + passive DNS) |
| `OSINTLLM_TEMPERATURE` | — (provider default)        | LLM temperature               |
| `OSINTLLM_SEED`      | — (random)                     | LLM seed                      |
| `OSINTLLM_MAX_VERIFY` | `2`                           | max correction round trips (verifier) |
| `OSINTLLM_REQUEST_TIMEOUT` | `30`                     | LLM request timeout (seconds) |
| `OSINTLLM_NO_CACHE`  | `0`                             | `1` to disable the cache      |
| `OSINTLLM_CACHE_DIR` | `.cache`                        | disk cache directory          |
| `OSINTLLM_CACHE_TTL` | `86400`                         | cache validity (seconds)      |

> The site (**Analysis** and **Benchmark** screens) can force either provider
> for a given request, without ever changing these variables on disk — see
> [docs/ARCHITECTURE.md](ARCHITECTURE.md).

Loop guardrails (in `config.py`): `max_iterations=8`,
`request_timeout=30s`.

## Cache & rate limiting

Every tool result is cached on disk (`.cache/`, 24 h TTL) — a 2nd identical
call is served without a network request. Errors (e.g. crt.sh returning 502)
are **never** cached. HTTP requests are spaced out per host (`http.py`).
Bypass the cache: `--no-cache` on the CLI or the "Use cache" checkbox in the
UI.

## Active mode and proxy

**Choosing the mode** — a *Passive / Active* selector in the form picks the
type of reconnaissance for each request. On the API side, this goes through
the `mode` parameter:

```text
GET /api/analyze?domain=example.com&mode=passive              # default
GET /api/analyze?domain=example.com&mode=active               # direct contact
GET /api/analyze?domain=example.com&mode=active&proxy=true    # via Tor/proxy
```

Any unknown value falls back to `passive` (the safest). On the CLI, active
mode is enabled with the `--active` flag and the proxy with `--proxy`
(`python main.py example.com --active --proxy`).

**Disguise in active mode.** The request that hits the target
(`tech_fingerprint`) is sent with a **random browser User-Agent** (never the
`osintllm` signature). When **"Via Tor / proxy"** is checked (active mode
only), that request is routed through a SOCKS5 proxy: the target then sees
the proxy's IP, not yours. Passive third-party sources (crt.sh,
VirusTotal…) stay direct, regardless of this setting.

<details>
<summary><strong>Going through Tor (free proxy)</strong></summary>

1. Install and start the Tor daemon locally:

   ```bash
   brew install tor   # macOS
   tor                # opens a SOCKS5 proxy on 127.0.0.1:9050
   ```

2. Run the analysis in active mode with the proxy checked (UI) or `--proxy`
   (CLI). Nothing else to configure: `OSINTLLM_PROXY_URL` defaults to
   `socks5h://127.0.0.1:9050` (the `h` makes DNS resolve through Tor, so the
   target domain doesn't leak). Tor Browser listens on port **9150**
   instead — in that case: `OSINTLLM_PROXY_URL=socks5h://127.0.0.1:9150`.

> ⚠️ Many sites **block or challenge Tor exit nodes** (captcha, 403):
> `tech_fingerprint` may fail on a hardened target. It's anonymous but
> conspicuous (the IP is identifiable as Tor). A VPN on the machine is often
> simpler if the goal is just not to expose your personal IP.

</details>
