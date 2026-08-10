# SPEC — abuseipdb-proxy

A small, self-hosted, read-only HTTP service that answers IP-reputation
questions against the AbuseIPDB APIv2 CHECK endpoint, for a single analyst on
the same machine. This document is the single source of truth: implementation,
tests, container and CI all cite it. Contentious choices are recorded as
numbered decisions (D1…) with rationale; empirical claims cite
`docs/research/NOTES.md` (findings F1…) and the raw captures in
`docs/research/captures/`.

## 1. Hard constraints (never violate)

- **Read-only upstream.** The service calls exactly one upstream endpoint,
  `GET https://api.abuseipdb.com/api/v2/check`, and never any mutating
  AbuseIPDB endpoint (REPORT, etc.). Read-only is semantic, not just an HTTP
  method choice.
- **Localhost-only.** The service is deployed with its port published on
  `127.0.0.1` only. No authentication of callers, by design: the trust
  boundary is the machine.
- **The API key lives in the environment** (`.env`, never committed), loaded
  via pydantic-settings. The key never appears in logs or responses.
- **English only** for everything that lands in the repository.

## 2. Decisions

- **D1 — Score and report window.** `verdict.score` is upstream's
  `abuseConfidenceScore`, unmodified — the same number the AbuseIPDB GUI
  shows (parity confirmed: F1). Measured, the score is invariant to
  `maxAgeInDays` (F1), so the window choice does not affect the verdict.
  Default `maxAgeInDays` sent upstream: **30** (the upstream default, F2),
  overridable per request via `max_age_days` (1–365). Note the GUI's
  "reported N times" counter is all-time and NOT reproducible via CHECK
  (F1); parity applies to the score only.
- **D2 — `known` semantics.** `known = (totalReports > 0) or isWhitelisted`,
  where `totalReports` is window-scoped (F3). Rationale: "known" answers
  "does AbuseIPDB currently know something actionable about this IP" —
  either someone reported it within the effective window, or AbuseIPDB
  actively vouches for it (whitelist, F5). An IP whose only reports are
  older than the window is `known: false` (F3: totalReports 0 with
  lastReportedAt 2022). A whitelisted IP with zero window reports is
  `known: true` with score 0.
- **D3 — Local input validation; non-global rejection.** The proxy parses
  the input with Python's `ipaddress` before any upstream call:
  1. Unparseable input → 400. (Upstream's 422 still burns daily quota, F8 —
     and local rejection is faster and deterministic.)
  2. A v4-mapped IPv6 address (`::ffff:a.b.c.d`) is **unwrapped** to the
     embedded IPv4 first. Rationale: upstream treats the mapped form as a
     separate identity with a blank record — `::ffff:8.8.8.8` has zero
     reports while `8.8.8.8` is whitelisted with 110 (F9); querying it as
     given would silently hand the analyst an empty reputation.
  3. The (unwrapped) address must satisfy `is_global and not is_multicast`
     (measured on Python 3.13, F6 note in NOTES "Open questions"):
     rejects RFC1918, loopback, link-local, CGNAT (100.64/10), TEST-NETs,
     benchmark, ULA, documentation, unspecified, broadcast — and multicast,
     which bare `is_global` lets through. Violation → 400 with a reason
     naming the category. Rationale: upstream answers such queries as if
     they were meaningful (192.168.1.1 "has" 16 reports, F6) — garbage that
     must not reach an analyst — and every avoided call conserves quota.
- **D4 — Error mapping.** "No data" is not an error (F4: upstream has no
  404 semantics; an unreported IP is a 200). Failures map as:

  | Condition | Our status | Body detail |
  |---|---|---|
  | input fails D3 | 400 | validation reason |
  | upstream 401 (bad/revoked key) | 502 | "upstream authentication failed — check ABUSEIPDB_API_KEY" |
  | upstream 429 (daily quota) | 429 | upstream detail, `Retry-After` header passed through |
  | upstream timeout / connection error | 504 | "upstream timeout/unreachable" |
  | upstream 422 or any other unexpected status/shape | 502 | "unexpected upstream response" + upstream status |

  Upstream error `detail` strings are passed through in the body where
  present (shapes: F7); the API key is never echoed. A 422 reaching us
  post-validation means our validator and upstream disagree — that is a bug
  surface, hence 502, not a pass-through.
- **D5 — Surface: single lookup endpoint.** CHECK only, single IP (v4/v6).
  No REPORTS, BLACKLIST or CHECK-BLOCK in v1. `verbose` is exposed as an
  optional passthrough flag: when set, upstream attaches per-report details
  which land, unmodified, inside `report` (F: `bad-tor-verbose.json`).
- **D6 — Threshold semantics.** `verdict.thresh_gte = (score >= threshold)`.
  `threshold` is an optional per-request integer 0–100; default comes from
  configuration (`SCORE_THRESHOLD`, default 30).
- **D7 — Transport rules (carried from the sibling project).** HTTP client
  is `requests`; **every** upstream call has an explicit timeout
  (configurable, default 5 s — `requests` has no default and would hang
  forever); **all endpoints are plain `def`** — `async def` is banned
  codebase-wide (blocking `requests` in sync endpoints runs in Starlette's
  threadpool; in `async def` it would freeze the event loop). Accepted side
  effect: httpx appears as a dev-only dependency via FastAPI's TestClient;
  service code stays requests-only.

## 3. HTTP API

### `GET /check/{ip}`

Path parameter: the IP address as text (IPv4 or IPv6; IPv6 colons are legal
in a path segment).

Query parameters (all optional):

| Param | Type | Default | Constraint |
|---|---|---|---|
| `threshold` | int | `SCORE_THRESHOLD` config | 0–100 |
| `max_age_days` | int | `MAX_AGE_DAYS` config (30) | 1–365 |
| `verbose` | bool | false | — |

Success — `200`, envelope:

```json
{
    "query": "<the IP exactly as asked>",
    "known": true,
    "verdict": {
        "score": 30,
        "thresh_gte": true
    },
    "report": { "...": "upstream `data` object, unmodified" }
}
```

- `query` echoes the caller's input verbatim (even when D3 unwrapped a
  v4-mapped address — the normalized form is visible in
  `report.ipAddress`).
- `known` per D2; `verdict.score` per D1; `verdict.thresh_gte` per D6.
- `report` is upstream's `data` object passed through unmodified (fields:
  NOTES "Transport"; includes `reports[]` when `verbose`).

Errors — status per D4, body is FastAPI-native:

```json
{ "detail": "<human-readable reason>" }
```

### `GET /health`

`200 {"status": "ok"}`. No upstream call, no key use — safe for container
smoke-tests and liveness probes.

## 4. Configuration

Loaded by pydantic-settings from the environment / `.env` (12-Factor). No
variable prefix; names as already established in `.env`:

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `ABUSEIPDB_API_KEY` | yes | — | APIv2 key; startup fails fast with a clear message if missing |
| `SCORE_THRESHOLD` | no | 30 | default for `threshold` (0–100) |
| `MAX_AGE_DAYS` | no | 30 | default for `max_age_days` (1–365) |
| `UPSTREAM_TIMEOUT_S` | no | 5 | per-call upstream timeout, seconds |

Standard proxy variables (`HTTPS_PROXY`, `NO_PROXY`, …) are honored as-is by
`requests` — documented as a configuration contract so a corp-side derived
image (CA certs + proxy at runtime) needs no changes here.

## 5. Upstream contract

`GET https://api.abuseipdb.com/api/v2/check` with headers `Key: <api key>`,
`Accept: application/json`; params `ipAddress`, `maxAgeInDays`, optionally
`verbose`. JSON API-style body: `data` on success, `errors[]` on failure
(F7). Free-tier quota 1000 checks/day, tracked via `X-RateLimit-*` headers,
reset at midnight UTC; **invalid queries also burn quota** (F8) — hence D3's
local validation. Quota headers are logged (see §7) but not exposed to
callers in v1.

## 6. Testing

- **Offline by design**: the suite runs with no network and no key. Upstream
  responses are faked from the captures in `docs/research/captures/` (the
  429 fixture is reconstructed, marked in-file; F10). CI depends on this.
- Optional live smoke tests behind `ABUSEIPDB_LIVE_TESTS=1` using the real
  key from `.env`; excluded by default and in CI.
- Coverage must include every D-decision edge measured in research:
  window-invariant score (D1), known/whitelisted/outside-window (D2),
  v4-mapped unwrap + each non-global category (D3), every error-mapping row
  (D4), threshold boundary `score == threshold` (D6).

## 7. Logging

Structured JSON to stdout/stderr only — no files, no volumes; rotation is
Docker's job. Each request logs: queried IP (normalized), effective
parameters, upstream status, upstream latency, our status, and the
`X-RateLimit-Remaining` value when present. Never the API key.

## 8. Container / CI / release

- **Dockerfile**: multi-stage, uv-based, classic-builder-compatible — no
  BuildKit-only syntax (`RUN --mount`, heredocs, `COPY --link`); must build
  on a legacy-builder machine even though CI runners would mask the
  breakage.
- **Compose**: publishes `127.0.0.1:8000:8000` only; `container_name`
  pinned.
- **CI**: offline test suite + container build + smoke-test (`/health`
  via the published port). No key in CI.
- **Release**: on `v<version>` tags; hard-fails on tag/pyproject version
  mismatch; publishes to ghcr.io with `org.opencontainers.image.source`
  label so the package auto-links to the (public) repo.

## 9. Non-goals (v1)

- Batch lookups, subnet/ASN/domain queries, REPORTS/BLACKLIST/CHECK-BLOCK.
- Caching of upstream responses (single analyst, 1000/day quota is ample;
  a cache would add staleness semantics for no measured need).
- Exposing quota state to callers; caller authentication; TLS (localhost
  trust boundary).
