# Facade envelope contract

**Contract version 1.** A change to anything this document requires bumps
the version.

This is the contract of a family of small, read-only HTTP facades in front
of reputation services, called upstreams here. A facade looks up one
artifact — a file hash, an IP address, a domain, a URL — at its upstream and
answers in one shape, so that a consumer is written once for every facade.
Each facade adds its own parameters and verdict details within these rules
and documents them in its own specification.

It has two implementations: **abuseipdb-proxy** (IP addresses, AbuseIPDB)
and **vt-proxy** (files, IP addresses, domains and URLs, VirusTotal). §9
lists what differs between them.

## 1. Scope

This version covers lookup endpoints (one artifact in, one reputation out),
health, and the error body. A facade may offer other endpoints, such as a
search; they follow the calling conventions (§2) and the error body (§5),
and their own specification gives their response.

## 2. Calling conventions

- Every lookup is `POST` with a JSON body (`Content-Type: application/json`,
  UTF-8), although it reads only. Read-only is a property of the facade,
  guaranteed by its specification: it calls only reading endpoints of its
  upstream. A body carries artifacts and free text, such as URLs and `msg`,
  safely; one calling convention serves every endpoint; consumers are
  programs.
- Every path carries the version prefix `/v1`. A lookup endpoint is named
  after what it does, for example `POST /v1/check` or `POST /v1/score`.
- No trailing slashes, and no redirects to fix them: a path with a trailing
  slash is an unknown path.
- Unknown fields in a request body are refused (`VALIDATION_ERROR`).
  Query-string parameters on a lookup are ignored.
- Unknown paths and wrong methods answer the error body (§5), never a
  framework's default body.
- The OpenAPI documents stay enabled at the framework's default paths (with
  FastAPI: `/docs`, `/redoc`, `/openapi.json`). Enabling them adds no
  outbound call: the facade serves the pages and the document, and the pages
  load their assets in the reader's browser.

## 3. Request

```json
{
  "artifact": "198.51.100.7",
  "<parameter>": "<value>",
  "msg": "case-4711"
}
```

- **`artifact`** (required): the thing looked up, as text; a non-empty
  string. The facade checks its content before any upstream call. Text that
  is not an artifact the facade can look up is `INVALID_ARTIFACT`, and the
  upstream is not consulted.
- **`msg`** (optional): a correlation string chosen by the consumer; a
  string or `null`, where `null` means absent; no length limit. It is echoed
  in `query.msg` and written to the facade's log line for a successful
  lookup (§8). It never appears in an error body and never influences
  behaviour.
- **A facade's own parameters** are optional and validated (type, range).
  Each has a default from the facade's configuration or its specification
  and is omitted to get it: an explicit `null` is a shape failure. Each is
  echoed in `query` with its effective value.
- **JSON types.** A consumer sends every field in its JSON type — strings
  as strings, integers as integers, booleans as booleans — and a facade
  answers any other type with `VALIDATION_ERROR`. It does not coerce: a
  coercion would turn a consumer's slip into a silently different query
  (`true` read as the integer 1).

## 4. Response envelope

```json
{
  "query": { "artifact": "198.51.100.7", "type": "ip", "<parameter>": "<effective value>", "msg": "case-4711" },
  "known": true,
  "verdict": { "score": 42, "thresh_gte": true },
  "report": { "…": "the upstream's object, verbatim" }
}
```

Exactly four top-level keys, always present:

- **`query`** — what was asked, with defaults applied: `artifact` as sent,
  `type`, every facade parameter with its effective value, and `msg` as sent
  or `null`. Nothing else.
- **`type`** is the family's vocabulary: `file | ip | domain | url`. It
  coexists with the upstream's own naming inside `report`, which is never
  renamed.
- **`known`** — a boolean: whether the upstream knows something about the
  artifact. Each facade defines it in its specification.
- **`verdict`** — the facade's computed layer. Two fields are common:
  `score`, the upstream's headline number for the artifact, unmodified, and
  `thresh_gte`, `score >= <the facade's threshold parameter>`. The parameter's
  name is the facade's own (`threshold`, `positives_thresh`). A facade may
  add fields of its own.
- **`report`** — the upstream's object for the artifact, verbatim: never
  renamed, filtered or converted.

**`known: false` takes one of two shapes.** If the upstream has no record
for an unknown artifact, `verdict` and `report` are `null`. If the upstream
always answers with a record, both stay present, with the score the upstream
gives. A `null` counts as present: the four keys are always there.

**No data is not an error.** An artifact the upstream knows nothing about is
`200` with `known: false`.

## 5. Errors

Every non-2xx answer has this body:

```json
{ "error": { "code": "UPSTREAM_QUOTA", "message": "…", "upstream": { "status": 429, "message": "…" } } }
```

- **`code`** — one of §5.1. Consumers branch on it.
- **`message`** — human text, the facade's own. Consumers never parse it.
- **`upstream`** — present only when the upstream answered with a body that
  parses as its error object: `status` (the upstream's HTTP status),
  `message` (its human text) and `code` (its own error code, only when the
  upstream has one). An HTML page from a load balancer, an empty body or any
  other shape yields no `upstream`, never a partial one. Its presence also
  tells who noticed a timeout.
- Nothing else; the value of `msg` never appears.

### 5.1 Codes

| `code` | HTTP | Meaning |
|---|---|---|
| `VALIDATION_ERROR` | 422 | the request's shape: a body that is not JSON or not an object, a missing or empty required field, a wrong JSON type, an explicit `null` for a parameter, a value out of range, an unknown field |
| `INVALID_ARTIFACT` | 422 | the request's content: the artifact is not one the facade can look up |
| `UPSTREAM_AUTH` | 502 | the upstream refused the facade's credentials (401, 403): the facade's misconfiguration, not the caller's |
| `UPSTREAM_QUOTA` | 429 | the upstream's rate or quota limit (429); its `Retry-After` header is passed through when present, never invented |
| `UPSTREAM_TIMEOUT` | 504 | the upstream could not be reached or did not answer in time: a connection error, a failed TLS verification, a client-side timeout, or the upstream's own 504 |
| `UPSTREAM_ERROR` | 502 | the upstream answered with any status not mapped above |
| `UPSTREAM_SCHEMA` | 502 | the upstream answered with its success status, with a body the facade cannot read |
| `NOT_FOUND` | 404 | unknown path |
| `METHOD_NOT_ALLOWED` | 405 | known path, wrong method |
| `INTERNAL` | 500 | unexpected failure inside the facade |

### 5.2 Mapping rules for an upstream

1. **Shape before content, both before the upstream.** `VALIDATION_ERROR`
   is decided by the request's form alone, `INVALID_ARTIFACT` by what the
   facade knows about artifacts; neither consults the upstream.
2. **The upstream's status picks the code.** Its body only feeds
   `upstream`.
3. **Unknown is not an error.** Whatever the upstream answers for an
   artifact it has no data on — a 404, an empty record — becomes `200` with
   `known: false`.
4. **Credentials are the facade's problem.** A 401 or 403 from the upstream
   is `502 UPSTREAM_AUTH`, never passed on as 401 or 403, which would tell
   the caller to authenticate.
5. **A failed TLS verification is a transport failure:**
   `504 UPSTREAM_TIMEOUT`. When only Python's strict X.509 checks cause it
   while they are on, the message names OpenSSL's reason and ends with
   `, see X509_STRICT`.

## 6. Health

```json
{ "status": "ok", "name": "<facade>", "version": "<package version>", "extra_ca": false, "x509_strict": true }
```

`GET /v1/health` answers these five fields, and makes no upstream call.
`extra_ca` is `true` when `CA_FILE` is loaded. `x509_strict` says whether
the TLS context that verifies the upstream carries Python's strict X.509
checks, read from that context. Every facade of the family reports both
trust fields.

## 7. Configuration conventions

- The upstream's API key comes from the environment only. It never appears
  in a log line or an answer.
- **`CA_FILE`** — a PEM file of certificate authorities trusted in addition
  to the default trust, for TLS with the upstream, directly or through a
  proxy tunnel. Verification is never switched off. A file that cannot be
  used refuses the start, with one line naming `CA_FILE`.
- **`X509_STRICT`** — `true` or `false`, default `true`. `false` clears
  only `ssl.VERIFY_X509_STRICT` on that context; the chain and the hostname
  are still verified. Any other value refuses the start.
- The standard proxy variables (`HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`) are
  honoured as the facade's HTTP client reads them.
- A base-URL override of the upstream exists for tests and mocks.

## 8. Deployment and logging

- A facade authenticates no caller. It must be reachable only by trusted
  callers on the same machine, typically by publishing its port on
  `127.0.0.1`: the trust boundary is the machine.
- It logs JSON lines on stdout: at least one line per successful lookup,
  carrying `msg` when the consumer sent one. No line carries the API key.

## 9. Implementations

| | abuseipdb-proxy | vt-proxy |
|---|---|---|
| Lookups | `POST /v1/check` | `POST /v1/score`, `/v1/score/file`, `/ip`, `/domain`, `/url` |
| Parameters | `threshold`, `max_age_days`, `verbose` | `positives_thresh` |
| `type` | `ip` | `file`, `ip`, `domain`, `url` |
| `known: false` | `verdict` and `report` present | `verdict` and `report` `null` |
| `verdict` beyond the common fields | — | `stats` |
| `upstream.code` | — (the upstream has none) | VirusTotal's error code |
| Other endpoints | — | `POST /v1/search/name` (§1) |

The differences this contract allows: a facade's own parameters and verdict
fields, the shape of `known: false` (§4), and `upstream.code`.

**Known deviation.** vt-proxy 0.3.0 coerces integers, against §3's rule on
JSON types: `"5"`, `5.0` and `true` pass as an integer, `true` as 1. A later
release of vt-proxy closes it; until then a consumer does not rely on it.

## 10. Checklist for a new facade

1. Name the lookup after what it does, under `/v1`; `POST` with a JSON body
   of `artifact`, the facade's parameters and `msg`.
2. Refuse unknown fields and wrong JSON types; give every parameter a
   default from configuration, refuse an explicit `null`, echo the effective
   value in `query`.
3. Check the artifact's content before any upstream call
   (`INVALID_ARTIFACT`).
4. Answer the four-key envelope: `query.type` from the vocabulary,
   `verdict.score` and `verdict.thresh_gte`, `report` verbatim; define
   `known` and pick the `known: false` shape your upstream gives.
5. Map upstream answers by §5.2, and build `upstream` only from a body that
   parses as the upstream's error object.
6. Answer unknown paths, wrong methods and internal failures with the error
   body; no trailing-slash redirects.
7. Serve `GET /v1/health` with its five fields.
8. Support `CA_FILE`, `X509_STRICT`, the proxy variables, the key in the
   environment, and a base-URL override for tests.
9. Keep the OpenAPI documents enabled; make the facade reachable only by
   trusted callers on the same machine (§8).
10. Log one JSON line per lookup, with `msg` when sent; never the key.
