# SPEC — abuseipdb-proxy

A small, self-hosted, read-only HTTP service that answers IP-reputation
questions against the AbuseIPDB APIv2 CHECK endpoint, for a single analyst on
the same machine. This document is the single source of truth: implementation,
tests, container and CI all cite it. Contentious choices are recorded as
numbered decisions (D1…) with rationale; empirical claims cite
`docs/research/NOTES.md` (findings F1…) and the raw captures in
`docs/research/captures/`. Revision 2 incorporates the pre-implementation
three-lens subagent audit (2026-08-10).

## 1. Hard constraints (never violate)

- **Read-only upstream.** The service calls exactly one upstream endpoint,
  `GET https://api.abuseipdb.com/api/v2/check`, and never any mutating
  AbuseIPDB endpoint (REPORT, etc.). Read-only is semantic, not just an HTTP
  method choice.
- **Localhost-only.** The service is deployed with its port published on
  `127.0.0.1` only. No authentication of callers, by design: the trust
  boundary is the machine.
- **The API key lives in the environment** (`.env`, never committed), loaded
  via pydantic-settings. The key never appears in logs or responses (§4
  mandates `SecretStr`; the key travels only in the upstream `Key` header,
  never in URLs, so client-library tracebacks cannot embed it).
- **English only** for everything that lands in the repository.

## 2. Decisions

- **D1 — Score and report window.** `verdict.score` is upstream's
  `abuseConfidenceScore`, unmodified — the same number the AbuseIPDB GUI
  shows (parity spot-checked on one IP/score value, F1). Measured, the score
  is invariant to `maxAgeInDays` (F1), so the window choice does not affect
  the score. Default `maxAgeInDays` sent upstream: **30** (the upstream
  default, F2), overridable per request via `max_age_days` (1–365). Note the
  GUI's "reported N times" counter is all-time and NOT reproducible via
  CHECK (F1); parity applies to the score only.
- **D2 — `known` semantics.**
  `known = (totalReports > 0) or isWhitelisted or (abuseConfidenceScore > 0)`,
  where `totalReports` is window-scoped (F3). Rationale: "known" answers
  "does AbuseIPDB currently know something actionable about this IP" —
  someone reported it within the effective window, or AbuseIPDB actively
  vouches for it (whitelist, F5), or upstream computes a non-zero score
  (which is window-invariant, F1 — without this clause a small
  `max_age_days` could yield the contradictory `known: false` +
  `thresh_gte: true` in one envelope; audit finding). An IP whose only
  reports are stale enough to have decayed to score 0 and fall outside the
  window is `known: false` (F3). A whitelisted IP with zero window reports
  is `known: true` with score 0.
- **D3 — Local input validation; non-global rejection.** The proxy parses
  the input with Python's `ipaddress` before any upstream call:
  1. Unparseable input → 400. (Upstream's 422 still burns daily quota, F8 —
     and local rejection is faster and deterministic.)
  2. A parsed IPv6 address with a non-empty `scope_id` (zone-id, e.g.
     `2606:4700:4700::1111%eth0`) → 400 "zone-id not allowed". Audit
     finding: a zone-id on a *global* address passes the `is_global` check,
     goes upstream, 422s and burns quota — it must die locally.
  3. A v4-mapped IPv6 address (`::ffff:a.b.c.d`) is **unwrapped** to the
     embedded IPv4. Rationale: upstream treats the mapped form as a separate
     identity with a blank record — `::ffff:8.8.8.8` has zero reports while
     `8.8.8.8` is whitelisted with 110 (F9); querying it as given would
     silently hand the analyst an empty reputation. Accepted v1 limitation:
     other v4-embedding schemes (NAT64 `64:ff9b::/96`, the deprecated
     compat `::a.b.c.d`, `::ffff:0:a.b.c.d`) are NOT unwrapped and reach
     upstream as distinct (blank) identities.
  4. The (unwrapped) address must satisfy `is_global and not is_multicast`
     (measured on Python 3.13, F11). The **normative** rejected set is:
     RFC1918, loopback, link-local, CGNAT (100.64/10), TEST-NETs,
     benchmark, ULA, IPv6 documentation (2001:db8::/32), unspecified,
     broadcast, multicast (which bare `is_global` lets through, F11).
     `ipaddress` is the implementation, not the definition: the test suite
     enumerates these categories explicitly, so an interpreter upgrade that
     shifts `is_global` surfaces as a test failure, not a silent contract
     change. Violation → 400 with a reason naming the category. Rationale:
     upstream answers such queries as if they were meaningful (192.168.1.1
     "has" 16 reports, F6) — garbage that must not reach an analyst — and
     every avoided call conserves quota.
  5. What goes upstream is always `str()` of the parsed, unwrapped address
     (canonical lowercase/compressed form) — never the caller's spelling.
     This makes `report.ipAddress` (upstream echoes the query form, F9
     capture) the canonical form, and makes log/response correlation
     deterministic across textual variants of one address.
- **D4 — Error mapping.** "No data" is not an error (F4: upstream has no
  404 semantics; an unreported IP is a 200). Failures map as:

  | Condition | Our status | Body `detail` (source) |
  |---|---|---|
  | input fails D3, or query-param validation fails | 400 | ours: validation reason |
  | upstream 401 (bad/revoked key) | 502 | ours, stable prefix `upstream-auth:` — "check ABUSEIPDB_API_KEY" |
  | upstream 429 (daily quota) | 429 | upstream `detail` passed through when parseable; `Retry-After` passed through when present |
  | upstream timeout / connection error | 504 | ours, stable prefix `upstream-timeout:` |
  | upstream 422 or any other unexpected status/shape | 502 | ours, stable prefix `upstream-unexpected:` + upstream status |

  Per-row body source is normative (audit finding: an earlier blanket
  "upstream detail is passed through" sentence contradicted the fixed-string
  rows). The stable `detail` prefixes are part of the contract so caller
  scripts can branch without parsing prose — in particular distinguishing
  permanent `upstream-auth:` (do not retry) from transient
  `upstream-unexpected:`/`upstream-timeout:`. The 429 mapping keys on the
  upstream **status code alone** and must tolerate a non-JSON body (CDN-era
  429s can be HTML — fall back to a generic detail) and an absent
  `Retry-After` (omit the header, never fabricate one). The API key is
  never echoed. A 422 reaching us post-validation means our validator and
  upstream disagree — with D3.2 in place that is a genuine bug surface,
  hence 502, not a pass-through.
- **D5 — Surface: single lookup endpoint.** CHECK only, single IP (v4/v6).
  No REPORTS, BLACKLIST or CHECK-BLOCK in v1. `verbose` is exposed as an
  optional passthrough flag: when set, upstream attaches per-report details
  which land, unmodified, inside `report` (NOTES §Transport /
  `captures/bad-tor-verbose.json`). The upstream `verbose` parameter is
  **presence-keyed**: it is sent (empty-valued) only when the caller's
  `verbose` is true and omitted entirely otherwise — a literal
  `verbose=false` would read as present upstream (audit finding, found
  independently by all three auditors).
- **D6 — Threshold semantics.** `verdict.thresh_gte = (score >= threshold)`.
  `threshold` is an optional per-request integer 0–100; default comes from
  configuration (`SCORE_THRESHOLD`, default 30). Degenerate case, by
  design: `threshold=0` makes `thresh_gte` vacuously true for every IP
  (score 0 >= 0) — useful for flag-everything sweeps, not a bug.
- **D7 — Transport rules (carried from the sibling project).** HTTP client
  is `requests`; **every** upstream call has an explicit timeout
  (configurable, default 5 s — `requests` has no default and would hang
  forever); **all endpoints are plain `def`** — `async def` is banned
  codebase-wide (blocking `requests` in sync endpoints runs in Starlette's
  threadpool; in `async def` it would freeze the event loop). All sync
  endpoints share that default threadpool (~40 threads), `/health`
  included — saturation by a burst of slow lookups delays liveness too;
  accepted for the single-analyst deployment. Accepted side effect: httpx
  appears as a dev-only dependency via FastAPI's TestClient; service code
  stays requests-only.
- **D8 — No automatic retries.** The upstream GET is idempotent, but every
  retry burns the shared daily quota (F8), so the proxy never retries on
  its own — callers see 429/502/504 and decide. Recorded as a decision so
  nobody "helpfully" bolts on urllib3 `Retry` defaults later.

## 3. HTTP API

### `GET /check/{ip}`

Path parameter: the IP address as text (IPv4 or IPv6; IPv6 colons are legal
in a path segment). `query` in the envelope echoes the **decoded** path
segment (percent-decoding applied by the server; e.g. a sent `%25` arrives
as `%`).

Query parameters (all optional):

| Param | Type | Default | Constraint |
|---|---|---|---|
| `threshold` | int | `SCORE_THRESHOLD` config | 0–100 |
| `max_age_days` | int | `MAX_AGE_DAYS` config (30) | 1–365 |
| `verbose` | bool | false | — |

Success — `200`, envelope:

```json
{
    "query": "<the IP as asked (decoded path segment)>",
    "known": true,
    "verdict": {
        "score": 30,
        "thresh_gte": true
    },
    "params": {
        "threshold": 30,
        "max_age_days": 30,
        "verbose": false
    },
    "report": { "...": "upstream `data` object, unmodified" }
}
```

- `query` echoes the caller's input (even when D3 unwrapped a v4-mapped
  address — the canonical form is visible in `report.ipAddress`, guaranteed
  by D3.5).
- `known` per D2; `verdict.score` per D1; `verdict.thresh_gte` per D6.
- `params` carries the **effective** values used for this evaluation
  (audit finding: without it, config-default changes silently reinterpret
  verdicts and a stored response cannot explain itself).
- `report` is upstream's `data` object passed through unmodified (fields:
  NOTES §Transport; includes `reports[]` when `verbose`).

Errors — status per D4; body is always a single human-readable string:

```json
{ "detail": "<reason>" }
```

FastAPI's native validation error (422 with a list-shaped `detail`) is
**not** part of this contract: a custom `RequestValidationError` handler
converts query-param validation failures to the same 400-with-string shape
as D3 rejections.

Routing-level statuses are explicitly **not** reputation semantics: 404
means "no such endpoint", never "IP unknown" (this service has no VT-style
404, F4), and 405 means wrong method. Because a CIDR typo
(`/check/8.8.8.0/24` — also reachable via `%2F`, which ASGI decodes before
routing) would otherwise surface as a bare 404, a catch-all route
`/check/{rest:path}` returns 400 "not a single IP address" for any
multi-segment path.

### `GET /health`

`200 {"status": "ok"}`. No upstream call, no key use — safe for container
smoke-tests and liveness probes. Note `/health` proves the process is up
and configured (settings load eagerly at startup, §4) — it does not probe
upstream reachability.

## 4. Configuration

Loaded by pydantic-settings from the environment / `.env` (12-Factor):

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `ABUSEIPDB_API_KEY` | yes | — | APIv2 key |
| `SCORE_THRESHOLD` | no | 30 | default for `threshold` (0–100) |
| `MAX_AGE_DAYS` | no | 30 | default for `max_age_days` (1–365) |
| `UPSTREAM_TIMEOUT_S` | no | 5 | per-call upstream timeout, seconds (> 0) |

- **Fail-fast, eagerly.** Settings are instantiated once at process
  startup, **before** the server binds; any config error exits nonzero with
  a clear message. A missing key, a **blank/whitespace** key (the classic
  template-copy accident), or any out-of-range value all abort startup —
  config values carry the same constraints as their per-request
  counterparts. Rationale (audit): lazily-loaded settings would let a
  fatally misconfigured container pass the `/health` smoke test.
- **`ABUSEIPDB_API_KEY` is typed `SecretStr`**; the raw value is unwrapped
  only at the point the upstream `Key` header is built. This keeps the key
  out of settings `repr()`s and pydantic `ValidationError` echoes.
- **Timeout semantics**: `UPSTREAM_TIMEOUT_S` is passed as requests'
  `(connect, read)` tuple; it bounds the connect phase and each inter-byte
  gap, not total wall time — a pathological trickling upstream is accepted
  as out of scope for v1.
- **Naming trade-off (recorded)**: `ABUSEIPDB_API_KEY` and
  `SCORE_THRESHOLD` keep the names already established in the local `.env`;
  `MAX_AGE_DAYS` and `UPSTREAM_TIMEOUT_S` are new. The un-prefixed names
  are fine in the dedicated container; in bare local runs, real environment
  variables override `.env` (pydantic-settings precedence), so a stray
  `SCORE_THRESHOLD` in the analyst's shell silently changes verdicts —
  accepted, container is the deployment target.
- Standard proxy variables (`HTTPS_PROXY`, `NO_PROXY`, …) are honored as-is
  by `requests` — documented as a configuration contract so a corp-side
  derived image (CA certs + proxy at runtime) needs no changes here.

## 5. Upstream contract

`GET https://api.abuseipdb.com/api/v2/check` with headers `Key: <api key>`,
`Accept: application/json`; params `ipAddress` (always the canonical form
per D3.5), `maxAgeInDays`, and `verbose` only when true (presence-keyed,
D5). JSON API-style body: `data` on success, `errors[]` on failure (F7).

All calls go through a single module-level `requests.Session` (connection
pooling; safe across threadpool threads here because no cookies or
per-request session state are used). No retries (D8).

Free-tier quota 1000 checks/day, tracked via `X-RateLimit-*` headers, reset
at midnight UTC; **invalid queries also burn quota** (F8) — hence D3's
local validation. The `X-RateLimit-Remaining` value is logged (§7) but
quota state is not exposed to callers in v1 — except the deliberate D4
exception: the 429 pass-through (upstream detail + `Retry-After`) *is*
quota state, and that is intentional.

## 6. Testing

- **Offline by design**: the suite runs with no network and no key. Upstream
  responses are faked from the captures in `docs/research/captures/` (the
  429 fixture is reconstructed, marked in-file; F10). CI depends on this.
- **Enforced, not assumed** (audit): a session-scoped guard fails any test
  that attempts a real network call, and test settings never read the
  repository `.env` — a single mock miss must not burn quota with the real
  key or flake in keyless CI.
- Optional live smoke tests run only when `ABUSEIPDB_LIVE_TESTS` equals the
  literal string `1`, using the real key from `.env`; excluded by default
  and in CI. Live assertions check response *shape and invariants* (types,
  envelope fields, score in 0–100) — never exact scores or report counts,
  which drift daily (F1).
- Coverage must include every D-decision edge measured in research:
  window-invariant score (D1), known for whitelisted / outside-window /
  score-only (D2), zone-id rejection, v4-mapped unwrap and each normative
  non-global category (D3 — this doubles as the interpreter-drift canary),
  every error-mapping row **including the degraded 429** (non-JSON body, no
  `Retry-After`) and the 400-with-string shape for query-param failures
  (D4), presence-keyed verbose (D5), threshold boundary `score ==
  threshold` and `threshold=0` (D6), and the catch-all `/check/a/b` → 400.

## 7. Logging

Structured JSON to stdout/stderr only — no files, no volumes; rotation is
Docker's job. Each request logs: ISO-8601 UTC timestamp, queried IP
(normalized = `str()` of the parsed, unwrapped address, D3.5), effective
parameters (as in `params`), upstream status and latency, our status, the
computed outcome (`score`, `known`, `thresh_gte`) — so a verdict can be
explained from logs a week later even though upstream data drifts — and
`X-RateLimit-Remaining` when present, at WARNING level once it drops below
50 (the log stream is the sole quota-visibility mechanism in v1, §9). Never
the API key.

Uvicorn's access log is disabled (the app's request log supersedes it) and
uvicorn error logs are routed through the same JSON formatter;
unhandled-exception tracebacks are the accepted exception to the
one-JSON-object-per-line rule.

## 8. Container / CI / release

- **Dockerfile**: multi-stage, uv-based, classic-builder-compatible — no
  BuildKit-only syntax (`RUN --mount`, heredocs, `COPY --link`,
  `FROM --platform=`); must build on a legacy-builder machine. Because CI
  runners would mask a violation, **CI enforces it**: a
  `DOCKER_BUILDKIT=0 docker build` gate (or, if the runner's Docker drops
  the legacy builder, a lint step failing on the banned syntax). The
  runtime stage drops to a dedicated non-root user (`app`, uid 10001) —
  defense in depth; derived images that need root (e.g. the README's
  corporate-CA recipe) must switch to `USER root` and back.
- **`.dockerignore` is mandatory and whitelist-style** (`*` then explicit
  `!` entries): nothing enters the build context unless listed, which
  structurally excludes `.env`, `.git/`, `docs/` and anything added in the
  future — the image is published publicly, gitleaks scans git history,
  not image layers, and a conventional `COPY . /app` would bake the real
  key into a public layer (audit blocker; default-deny verified on the
  legacy builder 2026-08-10, including `!dir/` re-inclusion and last-match
  re-exclusion of `**/__pycache__`). The key enters the container only via
  runtime environment, never at build time.
- **Compose**: publishes on `127.0.0.1` only; the host port is
  `ABUSEIPDB_PROXY_PORT` (default 8000, compose-only — the app never reads
  it); `container_name` pinned; container logs capped (json-file,
  10 MB × 3). The container runs a **single uvicorn process** (no `--workers`):
  a config error must crash the container visibly, not leave a master
  respawning dead workers while holding the port.
- **CI**: offline test suite + container build + smoke-test. The smoke test
  starts the container with a syntactically valid **dummy** key
  (`ABUSEIPDB_API_KEY=ci-dummy-key` — deliberately low-entropy so secret
  scanners never flag it) and polls `/health` via the published port with a
  bounded retry (~30 s) before failing. "No key in CI" means no *real*
  secret — without the dummy, fail-fast startup (§4) would make the smoke
  test impossible (audit blocker, found independently by two auditors).
- **Release**: on `v<version>` tags; the tag/pyproject version check is the
  **first step of the release job, strictly before any build/push step**;
  publishes to ghcr.io with `org.opencontainers.image.source` label so the
  package auto-links to the (public) repo.

## 9. Non-goals (v1)

- Batch lookups, subnet/ASN/domain queries, REPORTS/BLACKLIST/CHECK-BLOCK.
- Caching of upstream responses (single analyst, 1000/day quota is ample;
  a cache would add staleness semantics for no measured need).
- Exposing quota state to callers beyond the D4 429 pass-through; caller
  authentication; TLS (localhost trust boundary).
- Unwrapping non-mapped v4-embedded IPv6 schemes (D3.3 limitation).

## 10. Toolchain & repo docs

Python **3.13**, fully type-hinted; **uv** (`pyproject.toml` + `uv.lock`,
uv-first workflows); FastAPI + uvicorn; pydantic v2 + pydantic-settings;
**ruff** (lint + format); **pytest**. httpx is dev-only (D7). `CLAUDE.md`
exists from day one, opening with a "Hard constraints (never violate)"
section that mirrors §1 — the SPEC remains the single source of truth.
