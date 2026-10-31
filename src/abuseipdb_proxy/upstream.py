"""AbuseIPDB APIv2 CHECK client per SPEC §5, D7, D8, D9.

One module-level Session (connection pooling; no cookies or per-request
state, so it is safe across threadpool threads), explicit (connect, read)
timeout on every call, no retries.
"""

import ssl
from typing import Any

import requests
from requests.adapters import DEFAULT_POOLBLOCK, HTTPAdapter

from abuseipdb_proxy.settings import Settings

_session = requests.Session()


class _ContextAdapter(HTTPAdapter):
    """Hands one TLS context to every pool, direct and tunnelled (SPEC D9).

    requests still sets the bundle it resolves as each pool's ca_certs, and
    urllib3 loads that into this context at connect time, so the trust is that
    bundle, plus CA_FILE when it is set. The TLS with an https:// proxy endpoint
    itself takes urllib3's separate proxy_ssl_context, left unset, and keeps the
    default trust. Everything else, max_retries=0 included (D8), is requests'
    default.
    """

    def __init__(self, ssl_context: ssl.SSLContext) -> None:
        self._ssl_context = ssl_context  # first: HTTPAdapter.__init__ builds the pools
        super().__init__()

    def init_poolmanager(
        self, connections: int, maxsize: int, block: bool = DEFAULT_POOLBLOCK, **pool_kwargs: Any
    ) -> None:
        pool_kwargs["ssl_context"] = self._ssl_context
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> Any:
        proxy_kwargs["ssl_context"] = self._ssl_context
        return super().proxy_manager_for(proxy, **proxy_kwargs)


def use_context(context: ssl.SSLContext) -> None:
    """Route https:// of the one session through the upstream TLS context, in every
    configuration (SPEC D9)."""
    _session.mount("https://", _ContextAdapter(context))


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
