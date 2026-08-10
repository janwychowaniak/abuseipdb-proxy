# Research notes — AbuseIPDB APIv2 CHECK

Captured 2026-08-10 with `capture.py` (raw responses in `captures/`, API key
redacted). These findings feed the D-decisions in the upcoming SPEC; nothing
here is a decision yet.

## Transport

- `GET https://api.abuseipdb.com/api/v2/check`, key in the `Key` header,
  `Accept: application/json`. Body is JSON API-style: `data` on success,
  `errors[]` on failure.
- Success `data` fields (see `midscore-default.json`): `ipAddress`, `isPublic`,
  `ipVersion`, `isWhitelisted`, `abuseConfidenceScore`, `countryCode`,
  `usageType`, `isp`, `domain`, `hostnames[]`, `isTor`, `totalReports`,
  `numDistinctUsers`, `lastReportedAt` — plus `reports[]` when `verbose` is
  requested (`bad-tor-verbose.json`: `reportedAt`, `comment`, `categories[]`,
  `reporterId`, `reporterCountryCode`, `reporterCountryName`).

## Findings

1. **`abuseConfidenceScore` is window-invariant.** Same IP, `maxAgeInDays`
   30/90/365: score stays 30 while `totalReports` goes 2/23/31
   (`midscore-age*.json`); the saturated Tor IP stays 100 at 40/124/633
   (`bad-tor-age*.json`). `maxAgeInDays` filters `totalReports` and
   `reports[]` only — it does **not** recompute the score. Consequence: the
   sibling rule "score = what the GUI shows" holds for ANY window choice;
   the window choice only matters for report counts (and any `known`
   definition built on them). **GUI parity confirmed by eyeball 2026-08-10**:
   abuseipdb.com/check/87.98.154.146 shows "Confidence of Abuse is 30%" ==
   API score 30. The GUI's "reported 57 times" is an all-time counter —
   larger than any CHECK window (31 at maxAgeInDays=365) — so the GUI
   report COUNT is not reproducible via CHECK; the parity rule is about the
   score only. (Automated page fetch is Cloudflare-blocked; human glance
   was the way.)
2. **Upstream default window is 30 days**: `bad-tor-default.json` ==
   `bad-tor-age30.json` (40 reports both). Matches the official docs.
3. **`totalReports` is window-scoped; `lastReportedAt` is all-time.**
   `reported-outside-window.json` (193.0.6.139): `totalReports: 0` with
   `lastReportedAt: 2022-03-15`. The two candidate `known` definitions
   genuinely diverge on such IPs.
4. **Never-reported IP** (`never-reported.json`, 194.177.32.5): plain 200,
   score 0, `totalReports: 0`, `lastReportedAt: null`. No 404 semantics
   anywhere — the VT-style "unknown = 404" mapping does not exist here.
5. **Whitelisted ≠ unreported**: 8.8.8.8 is `isWhitelisted: true`, score 0,
   yet 110 reports in the 30-day window (`whitelisted-google-dns.json`).
   The whitelist forces the score to 0; reports keep accumulating.
6. **Upstream answers private/reserved IPs as if they were real queries.**
   192.168.1.1: 200, `isPublic: false`, **16 reports** of other people's LAN
   noise (`private-rfc1918.json`); TEST-NET 203.0.113.7 is even
   `isWhitelisted: true` (`reserved-testnet.json`). No upstream guard —
   whether to reject non-global IPs locally is ours to decide.
7. **Error shapes**: 422 invalid `ipAddress` carries
   `errors[0].source.parameter` (`invalid-string.json`); 401 bad key has
   `detail`/`status` only and **no rate-limit headers**
   (`error-bad-key.json`).
8. **Quota**: `X-RateLimit-Limit: 1000` (free tier, per day, resets midnight
   UTC per `X-RateLimit-Reset` epoch). Headers present on 200 **and** 422 —
   and Remaining decrements on 422 too, so invalid queries burn quota.
   A local pre-validation of IP syntax would conserve it.
9. **v4-mapped IPv6 is a separate, blank identity upstream.**
   `::ffff:8.8.8.8` → `ipVersion: 6`, 0 reports, not whitelisted
   (`v4mapped-google.json`), while `8.8.8.8` has 110 reports and is
   whitelisted. Querying the mapped form silently yields an empty
   reputation for a heavily-reported IP — the proxy should unwrap
   (`ipaddress`'s `.ipv4_mapped`) before querying, or reject the form.
   Note: Python 3.13's `is_global`/`is_private` already delegate to the
   embedded IPv4 for mapped addresses, so local validation is consistent
   either way.
10. **429 not captured live** — doing so would burn the full daily quota.
   `captures/error-quota-429.RECONSTRUCTED.json` is hand-built from the
   official docs (`Retry-After` in seconds until midnight UTC) and marked as
   such; replace with a live capture if we ever hit the limit naturally.

## Open questions for the SPEC (D-decisions to be)

- `known` semantics: window-scoped `totalReports > 0` vs all-time
  `lastReportedAt != null`; how `isWhitelisted` factors in (proposed lean:
  `known = totalReports > 0 or isWhitelisted`, window-scoped).
- Non-global IPs (RFC1918, loopback, link-local, reserved): reject locally
  with a 4xx before any upstream call (quota + honesty), or pass through?
  (Proposed lean: accept iff `is_global and not is_multicast` — measured on
  Python 3.13: bare `is_global` covers RFC1918/loopback/link-local/CGNAT/
  TEST-NET/benchmark/ULA/unspecified/broadcast but lets multicast through,
  since the IANA registry counts global-scope multicast as reachable.
  Plus: unwrap v4-mapped input first, see finding 9.)
- Default `maxAgeInDays` (lean: upstream default 30) and whether to expose
  it, and `verbose`, per request.
- Error mapping ours→caller: upstream 401 is proxy misconfiguration (5xx to
  caller?), 429 passes through with `Retry-After`, timeouts → 504, invalid
  IP → 4xx (local or passed-through 422).
