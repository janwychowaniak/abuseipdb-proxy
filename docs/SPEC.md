# SPEC — abuseipdb-proxy

A small, self-hosted, read-only HTTP service that answers IP-reputation
questions against the AbuseIPDB APIv2 CHECK endpoint, for a single analyst on
the same machine. This document is the single source of truth: implementation,
tests, container and CI all cite it. Contentious choices are recorded as
numbered decisions (D1…) with rationale; empirical claims cite
`docs/research/NOTES.md` (findings F1…) and the raw captures in
`docs/research/captures/`. Revision 2 incorporates the pre-implementation
three-lens subagent audit (2026-08-10). Revision 3 adds D9, extra CA trust
through `CA_FILE`, with the upstream base-URL override it needs for testing
(0.2.0).

## 1. Hard constraints (never violate)

- **Read-only upstream.** The service calls exactly one upstream endpoint,
  the CHECK endpoint at the configured base URL — `GET <base>/check`, base
  `https://api.abuseipdb.com/api/v2` unless `ABUSEIPDB_BASE_URL` overrides it
  for tests and mocks (§4) — and never any mutating AbuseIPDB endpoint
  (REPORT, etc.). Read-only is semantic, not just an HTTP method choice.
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
- **D9 — Extra CA trust (`CA_FILE`).** An optional PEM file whose
  certificates are trusted **in addition to** the default trust for TLS with
  the upstream, so that a deployment behind an egress proxy that intercepts
  TLS runs the published image unchanged. Unset or empty means absent:
  nothing is mounted on the session, and the client is exactly as without
  the variable. Certificate verification is never switched off, by this
  setting or any other.
  1. **Additive.** The trust is the union of what requests resolves without
     the variable (`REQUESTS_CA_BUNDLE`, then `CURL_CA_BUNDLE`, under
     `trust_env`; otherwise certifi's bundle) and the file; nothing from the
     default set is dropped, and every other TLS default stays. Mechanism:
     an `HTTPAdapter` on `https://` of the one session hands a single
     context — urllib3's own `create_urllib3_context()` plus the file — to
     its pool manager and to every proxy manager. requests still sets the
     bundle it resolves as each pool's `ca_certs`, and urllib3 loads that
     into the context at connect time. The union rests on that behaviour of
     `cert_verify`, which requests 2.32.3 and 2.32.4 did not have (a
     preloaded context, nothing loaded for `verify=True`): hence the floor
     `requests>=2.32.5`, and a test of the union on the `verify=True` path,
     the one a deployment takes (§6).
  2. **The tunnel property.** The union applies to TLS with the upstream
     both direct and inside a CONNECT tunnel (`HTTPS_PROXY`), the case a
     deployment behind a proxy uses. It is tested, not asserted (§6).
  3. **Stated limit.** The TLS with an `https://` proxy endpoint itself keeps
     requests' default trust: urllib3 builds it from a separate
     `proxy_ssl_context`, which the adapter leaves unset.
  4. **Validation, once, at startup.** One file, read once into memory; a
     replaced file takes effect on restart. Refused: a path that does not
     exist, cannot be read, or is not a regular file (checked before
     opening, since `open()` on a FIFO would block); content the loader
     rejects; content that yields no certificate. A value of only whitespace
     is a path. The loader takes the text as ASCII: a leading UTF-8 BOM is
     dropped and every other non-ASCII byte becomes `?`, so text outside the
     PEM blocks never decides and a stray byte inside one fails it, as with
     OpenSSL's own file loader. The count is taken on a fresh, empty context:
     a certificate without the CA flag counts, a root the default set
     already holds counts, duplicates within the file collapse. A refusal is
     one line on stderr and exit code 1 (§7); a missing API key is still
     reported first, with its own error.

  A failed verification stays on D4's transport-error path: 504
  `upstream-timeout: upstream unreachable (SSLError)`. Several files, a CA
  directory and reloading without a restart are out of scope.

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

`200`, with the service's name and version from the installed package
metadata, and whether `CA_FILE` is in use (D9):

```json
{ "status": "ok", "name": "abuseipdb-proxy", "version": "…", "extra_ca": false }
```

`extra_ca` is always present: `true` when `CA_FILE` is loaded, `false`
otherwise — no path, fingerprint or subject. No upstream call, no key use —
safe for container smoke-tests and liveness probes. Note `/health` proves
the process is up and configured (settings load eagerly at startup, §4) — it
does not probe upstream reachability.

## 4. Configuration

Loaded by pydantic-settings from the environment / `.env` (12-Factor):

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `ABUSEIPDB_API_KEY` | yes | — | APIv2 key |
| `SCORE_THRESHOLD` | no | 30 | default for `threshold` (0–100) |
| `MAX_AGE_DAYS` | no | 30 | default for `max_age_days` (1–365) |
| `UPSTREAM_TIMEOUT_S` | no | 5 | per-call upstream timeout, seconds (> 0) |
| `CA_FILE` | no | — (absent) | PEM file of certificate authorities trusted in addition to the default ones (D9) |
| `ABUSEIPDB_BASE_URL` | no | `https://api.abuseipdb.com/api/v2` | upstream prefix up to and including `/api/v2`; for tests and mocks |

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
- **`CA_FILE`** is only a path in the settings, so that a refusal is the
  service's own line rather than a pydantic error: the app factory checks it
  right after the settings (D9, §7). Unset or empty means absent.
- **`ABUSEIPDB_BASE_URL`** must start with `http://` or `https://`, else
  startup fails like any other configuration error; one trailing `/` is
  dropped, and the service appends `/check`. It exists so that tests and
  mocks can drive the real request path. The API key travels in the `Key`
  header to whatever host the value names, in clear over `http://`.
- **Naming trade-off (recorded)**: `ABUSEIPDB_API_KEY` and
  `SCORE_THRESHOLD` keep the names already established in the local `.env`;
  `MAX_AGE_DAYS` and `UPSTREAM_TIMEOUT_S` are new. The un-prefixed names
  are fine in the dedicated container; in bare local runs, real environment
  variables override `.env` (pydantic-settings precedence), so a stray
  `SCORE_THRESHOLD` in the analyst's shell silently changes verdicts —
  accepted, container is the deployment target. `CA_FILE` carries the
  sibling project's name on purpose, so one compose overlay serves both
  services.
- Standard proxy variables (`HTTPS_PROXY`, `NO_PROXY`, …) are honored as-is
  by `requests` — documented as a configuration contract, so a deployment
  behind a corporate proxy needs no changes here: the proxy at runtime, and
  its CA through `CA_FILE` (D9).

## 5. Upstream contract

`GET <base>/check` (base `https://api.abuseipdb.com/api/v2` unless
overridden, §4) with headers `Key: <api key>`,
`Accept: application/json`; params `ipAddress` (always the canonical form
per D3.5), `maxAgeInDays`, and `verbose` only when true (presence-keyed,
D5). JSON API-style body: `data` on success, `errors[]` on failure (F7).

All calls go through a single module-level `requests.Session` (connection
pooling; safe across threadpool threads here because no cookies or
per-request session state are used). With `CA_FILE`, its adapter is
mounted on `https://` of that same session at startup (D9). No retries
(D8).

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
- **Enforced, not assumed** (audit): a guard on every test fails any test
  that attempts a real network call, and test settings never read the
  repository `.env` — a single mock miss must not burn quota with the real
  key or flake in keyless CI. One exception, and only one: tests marked
  `loopback` may connect to numeric loopback addresses (`127.0.0.0/8`,
  `::1`), for TLS servers on loopback. The guard reads the address in every
  shape `connect()` receives and refuses names and `AF_UNIX` paths; its own
  tests pin both sides.
- **TLS on loopback** (D9): the extra-CA tests run against HTTPS servers
  and a plain CONNECT proxy on loopback, through the client a deployment
  builds (the one session with its adapter); the upstream answers with a
  frozen capture. Certificates are generated per run (`trustme`, dev-only)
  and never committed. A refusal is also checked once through the real
  entrypoint, in a subprocess.
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
  For D9: an authority from the file trusted, one in neither set refused;
  the union on both paths (`verify=True` with the default bundle replaced,
  and `REQUESTS_CA_BUNDLE`); the tunnel, with and without the file; every
  refusal with its exact line; the count (a leaf alone, a root the default
  set holds); reading against OpenSSL's own file loader; `extra_ca` and the
  startup line. For §4: the base-URL override and its validation.

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

With `CA_FILE` (D9), one startup line states the number of certificates
loaded — `"message": "ca_file_loaded"`, with `path` and `certificates` —
before uvicorn's own startup lines; none without it. A `CA_FILE` that cannot
be used ends the process before the server binds with exactly one line on
stderr and nothing on stdout, exit code 1:
`CA_FILE: <reason>: <path>`, the reason being `no such file`,
`not a regular file`, `cannot be read (<OS error>)` or
`no certificate could be loaded (<loader's reason>)`. The line never holds
certificate contents or another variable's value.

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
  defense in depth. A `HEALTHCHECK` probes `GET /health` (§3) every 30 s;
  without an orchestrator the state is informational (`docker ps`) — nothing
  auto-restarts on `unhealthy`.
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
  respawning dead workers while holding the port. `compose.ca.yml` is the
  overlay for `CA_FILE` (D9): it mounts `./ca.pem` read-only and sets the
  variable, with `create_host_path: false`, so that a missing file fails
  `up` at the mount instead of Docker creating a root-owned directory.
- **CI**: offline test suite + container build + archive round trip +
  smoke tests. The round trip runs `.github/scripts/archive-image.sh` on
  the CI-built image with `-` for the record, since an image never pushed
  has none: save by tag, the archive's configuration digest computed from
  its `manifest.json`, the image removed by Id and proven gone, the archive
  loaded back and its Id compared, the checksum verified. The smoke tests
  then run on the image loaded back, both with a read-only root filesystem
  and no tmpfs, since the service writes nothing:
  - without `CA_FILE`, `/health` with `"extra_ca":false`, and a non-global
    address rejected locally with 400;
  - with `CA_FILE` (a CA generated on the runner, mounted read-only),
    `"extra_ca":true` and exactly one `ca_file_loaded` line.

  Both use a syntactically valid **dummy** key
  (`ABUSEIPDB_API_KEY=ci-dummy-key` — deliberately low-entropy so secret
  scanners never flag it) and poll `/health` via the published port with a
  bounded retry (~30 s) before failing. "No key in CI" means no *real*
  secret — without the dummy, fail-fast startup (§4) would make the smoke
  tests impossible (audit blocker, found independently by two auditors).
- **Release** (`release.yml`, on `v<version>` tags), in two jobs:
  - `publish` (`contents: read`, `packages: write`). **First, before
    anything is built or pushed**, the gate: the tag, fetched as pushed,
    must be annotated (its message is the release notes) and equal `v` +
    the `pyproject.toml` version; each failure is one `::error::` line, and
    a failed gate burns no version. Then the suite on the tagged commit, the
    classic-builder build, the registry login only after the build, and the
    push of `<version>` and `latest` to ghcr.io; the Dockerfile's
    `org.opencontainers.image.source` label links the package to the
    (public) repo. The job records the **digest** (from `RepoDigests`) and
    the **image Id, the configuration digest read from the pushed
    manifest** (`docker manifest inspect <image>@<digest>`), never the
    runner's `.Id`: on the runner's containerd image store, `.Id` is not the
    configuration digest (measured in CI). The step summary carries three
    labelled lines: `digest`, `image Id (configuration digest)`, `Python`.
  - `archive` (`needs: publish`; the only job with `contents: write`).
    Pull by digest, tag `<version>`, run the archive script against the
    record, and put the checksum into the summary. Then fetch the tag again
    for its message, and create the GitHub Release from it with
    `abuseipdb-proxy-<version>.tar.gz` (the image saved by its full tag,
    through `gzip -n`) and its `.sha256`; on a re-run, both files are
    replaced and the notes rewritten from the tag. Post-condition: the
    published notes equal the tag message, trailing newlines aside. A
    failure here leaves the published image untouched, and re-running this
    job alone reaches the same end state.
  - **A tag is never pushed again, not even to fix its message**: that
    would run the release again and could publish the same version under
    another digest. A wrong line is corrected in `CHANGELOG.md`, as an
    erratum. `CHANGELOG.md` carries, per version, the notes with the
    digest, the configuration digest and the Python, filled in after
    `archive`.

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
**ruff** (lint + format); **pytest**. httpx (D7) and trustme (§6) are
dev-only. `CLAUDE.md` exists from day one, opening with a "Hard constraints
(never violate)" section that mirrors §1 — the SPEC remains the single source
of truth.
