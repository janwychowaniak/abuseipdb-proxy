# abuseipdb-proxy

Small, self-hosted, **read-only** HTTP proxy answering IP-reputation
questions against the [AbuseIPDB](https://www.abuseipdb.com/) APIv2 CHECK
endpoint — built for a single analyst on the same machine. Localhost-only,
no caller auth, key in the environment. Full behavioral contract:
[`docs/SPEC.md`](docs/SPEC.md).

## Quickstart

Using the published image:

```bash
cp .env.example .env          # then put your real APIv2 key in it
docker run -d --name abuseipdb-proxy --env-file .env \
  -p 127.0.0.1:8000:8000 ghcr.io/janwychowaniak/abuseipdb-proxy:latest
curl -s 127.0.0.1:8000/check/87.98.154.146 | jq
```

From source: `docker compose up -d --build`. Without Docker (requires
[uv](https://docs.astral.sh/uv/)):

```bash
uv sync
uv run uvicorn --factory abuseipdb_proxy.app:create_app --host 127.0.0.1 --port 8000
```

## API

`GET /check/{ip}` — single IPv4/IPv6 lookup. Optional query params:
`threshold` (0–100), `max_age_days` (1–365), `verbose` (attach per-report
details).

```json
{
    "query": "87.98.154.146",
    "known": true,
    "verdict": { "score": 30, "thresh_gte": true },
    "params": { "threshold": 30, "max_age_days": 30, "verbose": false },
    "report": { "…": "raw upstream data, unmodified" }
}
```

Response fields:

- `known` — AbuseIPDB currently knows something actionable about this IP:
  it was reported within the `max_age_days` window, **or** it is
  whitelisted, **or** its score is non-zero. An IP whose only reports are
  stale is `known: false`.
- `verdict.score` — AbuseIPDB's `abuseConfidenceScore`, exactly the number
  the GUI shows. The score is *window-invariant*: `max_age_days` filters
  `report.totalReports` and the `verbose` report list, never the score.
- `verdict.thresh_gte` — `score >= threshold`.
- `params` — the **effective** values used for this evaluation (config
  defaults fill in whatever you omitted), so a stored response can always
  explain its own verdict.
- `report` — the upstream `data` object, unmodified (whitelist flag,
  ISP/usage-type, `lastReportedAt`, …; plus `reports[]` when `verbose`).

Behavior notes:

- Non-global addresses (RFC1918, loopback, CGNAT, multicast, …) are rejected
  locally with `400` — they never reach upstream or burn quota.
- Error statuses: `400` invalid input, `429` upstream quota (with
  `Retry-After` when upstream provides it), `502` upstream auth/anomaly,
  `504` upstream timeout. Bodies are `{"detail": "<reason>"}` with stable
  prefixes (`upstream-auth:`, `upstream-timeout:`, `upstream-unexpected:`).
- `404` is a routing status ("no such endpoint"), **never** "IP unknown".

`GET /health` — liveness; no upstream call.

## Configuration (environment / `.env`)

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `ABUSEIPDB_API_KEY` | yes | — | AbuseIPDB APIv2 key |
| `SCORE_THRESHOLD` | no | 30 | default `threshold` |
| `MAX_AGE_DAYS` | no | 30 | default report window (days) |
| `UPSTREAM_TIMEOUT_S` | no | 5 | upstream timeout (seconds) |

Compose additionally interpolates `ABUSEIPDB_PROXY_PORT` (default 8000) as
the host port published on `127.0.0.1`. It is compose-only — the app never
reads it, so it has no effect under plain `docker run`.

## Logs

Structured JSON, one object per line, to stdout only — read with
`docker logs abuseipdb-proxy`. Every request line carries the effective
parameters, the computed verdict and upstream latency, plus AbuseIPDB's
`X-RateLimit-Remaining`; the level switches to `WARNING` once fewer than 50
daily requests remain (free tier: 1000/day). The log stream is the only
quota-visibility mechanism. Under compose the container log is capped
(json-file, 10 MB × 3 files); the Quickstart `docker run` path has no cap
unless you pass `--log-opt`.

## Deploying behind a corporate proxy

Egress proxy is runtime configuration, not a code concern — set
`HTTPS_PROXY`/`NO_PROXY` in the container environment. If your proxy
intercepts TLS, add its CA in a thin derived image and point `requests` at
the system store (note: `requests` trusts only its bundled certifi by
default and ignores `SSL_CERT_FILE` — use `REQUESTS_CA_BUNDLE`):

```dockerfile
FROM ghcr.io/janwychowaniak/abuseipdb-proxy:0.1.0
COPY corp-ca.crt /usr/local/share/ca-certificates/
RUN update-ca-certificates
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
```

## Development

```bash
uv run pytest -q              # offline: no network, no key, by design
uv run ruff check . && uv run ruff format --check .
ABUSEIPDB_LIVE_TESTS=1 uv run pytest -q -m live   # optional live smoke (real key)
```

Releases: a `v<version>` tag matching `pyproject.toml` publishes the image
to ghcr.io via CI.

[MIT](LICENSE) license.
