"""AbuseIPDB APIv2 CHECK client per SPEC §5, D7, D8.

One module-level Session (connection pooling; no cookies or per-request
state, so it is safe across threadpool threads), explicit (connect, read)
timeout on every call, no retries.
"""

import requests

from abuseipdb_proxy.settings import Settings

_session = requests.Session()


def check(
    settings: Settings, canonical_ip: str, max_age_days: int, verbose: bool
) -> requests.Response:
    params: dict[str, str] = {"ipAddress": canonical_ip, "maxAgeInDays": str(max_age_days)}
    if verbose:
        # Presence-keyed upstream (D5): sent empty-valued only when true,
        # omitted entirely otherwise — a literal verbose=false reads as
        # present upstream.
        params["verbose"] = ""
    timeout = settings.upstream_timeout_s
    return _session.get(
        f"{settings.abuseipdb_base_url}/check",
        headers={
            "Key": settings.abuseipdb_api_key.get_secret_value(),
            "Accept": "application/json",
        },
        params=params,
        timeout=(timeout, timeout),
    )
