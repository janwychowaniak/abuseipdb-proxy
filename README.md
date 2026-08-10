# abuseipdb-proxy

Small, self-hosted, **read-only** HTTP proxy answering IP-reputation
questions against the [AbuseIPDB](https://www.abuseipdb.com/) APIv2 CHECK
endpoint — built for a single analyst on the same machine. Localhost-only,
no caller auth, key in the environment. Full behavioral contract:
[`docs/SPEC.md`](docs/SPEC.md).

## Quickstart

```bash
cp .env.example .env          # then put your real APIv2 key in it
docker compose up -d
curl -s 127.0.0.1:8000/check/87.98.154.146 | jq
```

Without Docker:

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

- `verdict.score` is AbuseIPDB's `abuseConfidenceScore`, exactly the number
  the GUI shows.
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

Standard proxy variables (`HTTPS_PROXY`, `NO_PROXY`, …) are honored as-is.

## Development

```bash
uv run pytest -q              # offline: no network, no key, by design
uv run ruff check . && uv run ruff format --check .
ABUSEIPDB_LIVE_TESTS=1 uv run pytest -q -m live   # optional live smoke (real key)
```

MIT license.
