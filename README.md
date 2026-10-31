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

Prebuilt images are published on version tags:
`docker pull ghcr.io/janwychowaniak/abuseipdb-proxy:0.2.0` (`latest` tracks
the newest release). The compose file uses that same `latest` name:
`docker compose pull` fetches the published image, while
`docker compose up -d --build` builds it from your checkout. A host without
registry access can load a release file instead, see
[Using a release file on a host without registry access](#using-a-release-file-on-a-host-without-registry-access).

Without Docker (requires [uv](https://docs.astral.sh/uv/)):

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
  `504` upstream timeout or connection failure, a failed TLS verification
  included. Bodies are `{"detail": "<reason>"}` with stable prefixes
  (`upstream-auth:`, `upstream-timeout:`, `upstream-unexpected:`).
- `404` is a routing status ("no such endpoint"), **never** "IP unknown".

`GET /health` — liveness; no upstream call:

```json
{ "status": "ok", "name": "abuseipdb-proxy", "version": "…", "extra_ca": false, "x509_strict": true }
```

`version` is the running package's version. `extra_ca` turns `true` when the
service trusts an extra certificate authority (`CA_FILE`). `x509_strict`
turns `false` when Python's strict X.509 checks are relaxed (`X509_STRICT`).
See [Deploying behind a corporate proxy](#deploying-behind-a-corporate-proxy)
for both.

## Configuration (environment / `.env`)

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `ABUSEIPDB_API_KEY` | yes | — | AbuseIPDB APIv2 key |
| `SCORE_THRESHOLD` | no | 30 | default `threshold` |
| `MAX_AGE_DAYS` | no | 30 | default report window (days) |
| `UPSTREAM_TIMEOUT_S` | no | 5 | upstream timeout (seconds) |
| `CA_FILE` | no | — | PEM file of extra CA certificates, trusted in addition to the default ones; unset or empty: none ([corporate proxy](#deploying-behind-a-corporate-proxy)) |
| `X509_STRICT` | no | `true` | `false` relaxes Python's strict X.509 checks, for a proxy authority that fails them; unset or empty: `true` ([strict checks](#an-authority-that-fails-pythons-strict-checks)) |
| `ABUSEIPDB_BASE_URL` | no | `https://api.abuseipdb.com/api/v2` | upstream prefix, for tests and mocks |
| `HTTPS_PROXY` / `NO_PROXY` | no | — | standard egress-proxy variables, honored as-is |

`ABUSEIPDB_BASE_URL` replaces the prefix up to and including `/api/v2`, and
the service appends `/check` — for example
`ABUSEIPDB_BASE_URL=http://127.0.0.1:9000/api/v2` for a local mock. It is for
tests and mocks only: the API key travels in the `Key` header to whatever
host the value names, in clear when the value is `http://`.

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

The egress proxy is runtime configuration: set `HTTPS_PROXY` / `NO_PROXY` in
the container environment (`.env`), and AbuseIPDB traffic goes through it.

If the proxy intercepts TLS, give the service its certificate authority with
`CA_FILE`, and run the published image unchanged:

1. Put the proxy's CA certificate, in PEM, next to the compose files as
   `ca.pem`: its root or, where the proxy signs with an intermediate, the
   issuing chain (several certificates may share the file). The service runs
   as uid 10001, so the file must be readable by it; a CA certificate is
   public material, so mode `0644` is the natural choice.
2. Start with the overlay that mounts the file read-only and sets the
   variable (Compose v2):

   ```bash
   docker compose -f compose.yml -f compose.ca.yml up -d
   ```

   Without `ca.pem`, `up` fails at the mount instead of creating anything.

   The legacy `docker-compose` 1.x rejects `create_host_path`. With it, use
   the short bind syntax in an overlay of your own instead:

   ```yaml
   services:
     abuseipdb-proxy:
       environment:
         CA_FILE: /etc/abuseipdb-proxy/ca.pem
       volumes:
         - ./ca.pem:/etc/abuseipdb-proxy/ca.pem:ro
   ```

   Without `ca.pem`, Docker then creates a root-owned directory of that name
   and the service refuses to start with `not a regular file`, so put the
   file in place before `up`.

`GET /health` then says `"extra_ca": true`, and the log holds one
`ca_file_loaded` line with the number of certificates loaded. A file that
cannot be used stops the start with one line on stderr, for example
`CA_FILE: no such file: /etc/abuseipdb-proxy/ca.pem`. If the file lacks the
authority the proxy signs with, lookups fail with `504`
`upstream-timeout: upstream unreachable (SSLError)`.

The certificates are trusted **in addition to** the default ones, never
instead of them. *`CA_FILE` adds trust, and `X509_STRICT` relaxes the strict
checks, for TLS with AbuseIPDB, directly or through a proxy tunnel; the TLS
with an `https://` proxy endpoint itself keeps the client's default trust
(certifi's bundle, or what `REQUESTS_CA_BUNDLE` selects) and its strict
checks.*

Verification is never switched off. The authority, and the certificates the
proxy issues under it, must pass Python's strict X.509 checks: CA basic
constraints marked critical, a key usage that permits certificate signing,
key identifiers, and subject alternative names on the issued certificates.
For an authority that cannot pass them, see
[An authority that fails Python's strict checks](#an-authority-that-fails-pythons-strict-checks).

`REQUESTS_CA_BUNDLE` still works as a wholesale replacement of the default
bundle; `CA_FILE` adds to whatever it selects. (`requests` ignores
`SSL_CERT_FILE`.)

### An authority that fails Python's strict checks

**Symptom.** Every lookup fails with `504`, although `CA_FILE` holds the
proxy's authority. The response's `detail`, and the `detail` of the log line,
say:

```text
upstream-timeout: upstream unreachable (SSLError); TLS: Basic Constraints of CA cert not marked critical, see X509_STRICT
```

**Cause.** RFC 5280 (§4.2.1.9) requires a CA certificate to mark its Basic
Constraints critical, and Python 3.13 enforces this by default, so an
authority issued without the marker is refused even though it is trusted.

**Remedy**, when the authority cannot be reissued: set `X509_STRICT: "false"`
next to `CA_FILE` in the overlay; `compose.ca.yml` carries the line,
commented out. `GET /health` then says `"x509_strict": false`, and the log
holds one `x509_strict_disabled` warning. Verification stays on: the chain
must still lead to a trusted authority, and the hostname must still match.

**Blast radius.** `false` relaxes the RFC 5280 conformance checks for every
chain the service verifies, the public AbuseIPDB chain included, and the flag
gates more than Basic Constraints criticality: key identifiers, key usage and
names as well.

## Using a release file on a host without registry access

From 0.2.0, every release on GitHub carries the published image as a file,
`abuseipdb-proxy-<version>.tar.gz` (the image saved by its full tag), with
`abuseipdb-proxy-<version>.tar.gz.sha256` beside it. On the target host:

```bash
sha256sum -c abuseipdb-proxy-0.2.0.tar.gz.sha256
docker load -i abuseipdb-proxy-0.2.0.tar.gz
docker image inspect --format '{{.Id}}' ghcr.io/janwychowaniak/abuseipdb-proxy:0.2.0
```

The last line must print the image Id (configuration digest) that
[`CHANGELOG.md`](CHANGELOG.md) records for the version. The Id survives the
transfer where the registry digest does not: on Docker's default `overlay2`
image store it is the digest of the image's configuration, which the archive
carries byte for byte. Before it attaches the file, the release workflow
checks that the archive carries the configuration digest it published, and
loads the archive back into a store without the image.

The same Id can be checked without Docker: the archive's `manifest.json`
names the configuration blob, and that blob's SHA-256 is the Id.

```bash
config=$(tar -xzOf abuseipdb-proxy-0.2.0.tar.gz manifest.json | grep -o '"Config":"[^"]*"' | cut -d'"' -f4)
tar -xzOf abuseipdb-proxy-0.2.0.tar.gz "$config" | sha256sum   # the Id, without "sha256:"
```

The archive loads under `ghcr.io/janwychowaniak/abuseipdb-proxy:0.2.0`, while
the shipped `compose.yml` names `…:latest`. Either retag the loaded image:

```bash
docker tag ghcr.io/janwychowaniak/abuseipdb-proxy:0.2.0 ghcr.io/janwychowaniak/abuseipdb-proxy:latest
```

or pin the version in an override file of your own, for example
`compose.pin.yml`, used as
`docker compose -f compose.yml -f compose.pin.yml up -d`:

```yaml
services:
  abuseipdb-proxy:
    image: ghcr.io/janwychowaniak/abuseipdb-proxy:0.2.0
```

Either way, start without `--build`: the image is already there.

## Development

```bash
uv run pytest -q              # offline: no network, no key, by design
uv run ruff check . && uv run ruff format --check .
ABUSEIPDB_LIVE_TESTS=1 uv run pytest -q -m live   # optional live smoke (real key)
```

Releases: an annotated `v<version>` tag matching `pyproject.toml` publishes
the image to ghcr.io via CI, and attaches it, as
`abuseipdb-proxy-<version>.tar.gz` with its `.sha256`, to the tag's GitHub
Release.

[MIT](LICENSE) license.
