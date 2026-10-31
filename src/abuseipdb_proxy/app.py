"""FastAPI application — all endpoints are plain `def` (SPEC D7).

Run: uvicorn --factory abuseipdb_proxy.app:create_app
The factory instantiates Settings eagerly, so a misconfigured process dies
before the server binds (SPEC §4); X509_STRICT and then CA_FILE are checked
right after (D10, D9).
"""

import logging
import time
from importlib.metadata import metadata

import requests
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from abuseipdb_proxy import ca, tls, upstream
from abuseipdb_proxy.ipcheck import InvalidIPError, validate_ip
from abuseipdb_proxy.jsonlog import configure_logging
from abuseipdb_proxy.settings import Settings

logger = logging.getLogger("abuseipdb_proxy")

_RATELIMIT_WARN_BELOW = 50  # SPEC §7: the log stream is the sole quota signal


def _log_check(
    our_status: int,
    query: str,
    params: dict[str, object],
    normalized: str | None = None,
    upstream_status: int | None = None,
    upstream_ms: int | None = None,
    score: int | None = None,
    known: bool | None = None,
    thresh_gte: bool | None = None,
    ratelimit_remaining: int | None = None,
    detail: str | None = None,
) -> None:
    fields: dict[str, object] = {"event": "check", "our_status": our_status, "query": query}
    fields["params"] = params
    for key, value in (
        ("ip", normalized),
        ("upstream_status", upstream_status),
        ("upstream_ms", upstream_ms),
        ("score", score),
        ("known", known),
        ("thresh_gte", thresh_gte),
        ("ratelimit_remaining", ratelimit_remaining),
        ("detail", detail),
    ):
        if value is not None:
            fields[key] = value
    level = logging.INFO
    if ratelimit_remaining is not None and ratelimit_remaining < _RATELIMIT_WARN_BELOW:
        level = logging.WARNING
    logger.log(level, "check", extra=fields)


def _remaining(resp: requests.Response) -> int | None:
    raw = resp.headers.get("X-RateLimit-Remaining", "")
    return int(raw) if raw.isdigit() else None


def _x509_strict(value: str | None) -> bool:
    """X509_STRICT as a boolean; unset or empty means true (D10).

    A value that is neither true nor false ends the process here, the way a
    CA_FILE that cannot be used does.
    """
    try:
        return tls.parse_x509_strict(value)
    except tls.X509StrictError as exc:
        raise SystemExit(str(exc)) from None


def _ca_file(path: str | None) -> str | None:
    """The PEM text of CA_FILE, or None when it is unset or empty (D9).

    A file that cannot be used ends the process here: uvicorn prints a SystemExit
    carrying the refusal line and nothing else, so that line is the only output.
    """
    if not path:
        return None
    try:
        pem, count = ca.load_ca_file(path)
    except ca.CAFileError as exc:
        raise SystemExit(str(exc)) from None
    logger.info(
        "ca_file_loaded", extra={"event": "ca_file_loaded", "path": path, "certificates": count}
    )
    return pem


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    configure_logging()
    strict = _x509_strict(settings.x509_strict)  # before CA_FILE is read (D10)
    pem = _ca_file(settings.ca_file)
    # One context in every configuration, with or without CA_FILE (D9), carrying
    # the flag X509_STRICT decides (D10).
    context = tls.upstream_context(pem, strict)
    upstream.use_context(context)
    if not strict:
        logger.warning("x509_strict_disabled", extra={"event": "x509_strict_disabled"})
    extra_ca = pem is not None
    package = metadata("abuseipdb-proxy")
    name, version = package["Name"], package["Version"]
    app = FastAPI(title="abuseipdb-proxy", docs_url=None, redoc_url=None)

    @app.exception_handler(RequestValidationError)
    def _validation_to_400(request: Request, exc: RequestValidationError) -> JSONResponse:
        # SPEC §3: FastAPI's native 422-with-a-list shape is not part of the
        # contract; query-param failures get the same 400-with-string as D3.
        reasons = "; ".join(
            "{}: {}".format(".".join(str(loc) for loc in err["loc"]), err["msg"])
            for err in exc.errors()
        )
        return JSONResponse(status_code=400, content={"detail": f"validation error: {reasons}"})

    @app.get("/health")
    def health() -> dict[str, object]:
        # Liveness only: no upstream call, no key use (SPEC §3). x509_strict is
        # read from the upstream context itself, not from the setting (D10).
        return {
            "status": "ok",
            "name": name,
            "version": version,
            "extra_ca": extra_ca,
            "x509_strict": tls.is_strict(context),
        }

    @app.get("/check/{ip}")
    def check(
        ip: str,
        threshold: int | None = Query(default=None, ge=0, le=100),
        max_age_days: int | None = Query(default=None, ge=1, le=365),
        verbose: bool = False,
    ) -> dict[str, object]:
        eff: dict[str, object] = {
            "threshold": threshold if threshold is not None else settings.score_threshold,
            "max_age_days": max_age_days if max_age_days is not None else settings.max_age_days,
            "verbose": verbose,
        }

        try:
            parsed = validate_ip(ip)
        except InvalidIPError as exc:
            _log_check(400, ip, eff, detail=str(exc))
            raise HTTPException(status_code=400, detail=str(exc)) from None
        canonical = str(parsed)  # D3.5: upstream always receives the canonical form

        started = time.perf_counter()
        try:
            resp = upstream.check(settings, canonical, eff["max_age_days"], verbose)
        except requests.exceptions.RequestException as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            kind = (
                "no response within the configured timeout"
                if isinstance(exc, requests.exceptions.Timeout)
                else f"upstream unreachable ({type(exc).__name__})"
            )
            detail = f"upstream-timeout: {kind}"
            if tls.is_strict(context):
                # D10: a failure only the strict X.509 checks cause names its reason
                detail += tls.strict_hint(exc)
            _log_check(504, ip, eff, normalized=canonical, upstream_ms=elapsed, detail=detail)
            raise HTTPException(status_code=504, detail=detail) from None
        elapsed = int((time.perf_counter() - started) * 1000)
        remaining = _remaining(resp)

        def _fail(status: int, detail: str, headers: dict[str, str] | None = None) -> HTTPException:
            _log_check(
                status,
                ip,
                eff,
                normalized=canonical,
                upstream_status=resp.status_code,
                upstream_ms=elapsed,
                ratelimit_remaining=remaining,
                detail=detail,
            )
            return HTTPException(status_code=status, detail=detail, headers=headers)

        if resp.status_code == 401:
            raise _fail(
                502, "upstream-auth: upstream authentication failed — check ABUSEIPDB_API_KEY"
            )
        if resp.status_code == 429:
            # D4: keyed on status alone; tolerate non-JSON bodies and a
            # missing Retry-After (omit, never fabricate).
            try:
                detail = str(resp.json()["errors"][0]["detail"])
            except (ValueError, KeyError, IndexError, TypeError):
                detail = "upstream daily rate limit exceeded"
            retry_after = resp.headers.get("Retry-After")
            headers = {"Retry-After": retry_after} if retry_after else None
            raise _fail(429, detail, headers)
        if resp.status_code != 200:
            raise _fail(502, f"upstream-unexpected: upstream returned HTTP {resp.status_code}")

        try:
            data = resp.json()["data"]
            score = data["abuseConfidenceScore"]
        except (ValueError, KeyError, TypeError):
            raise _fail(502, "upstream-unexpected: response shape not recognized") from None
        if not isinstance(score, int):
            raise _fail(502, "upstream-unexpected: response shape not recognized")

        # D2: known = reported-in-window OR whitelisted OR non-zero score.
        known = data.get("totalReports", 0) > 0 or bool(data.get("isWhitelisted")) or score > 0
        thresh_gte = score >= eff["threshold"]  # D6

        _log_check(
            200,
            ip,
            eff,
            normalized=canonical,
            upstream_status=resp.status_code,
            upstream_ms=elapsed,
            score=score,
            known=known,
            thresh_gte=thresh_gte,
            ratelimit_remaining=remaining,
        )
        return {
            "query": ip,
            "known": known,
            "verdict": {"score": score, "thresh_gte": thresh_gte},
            "params": eff,
            "report": data,
        }

    @app.get("/check/{rest:path}")
    def check_catchall(rest: str) -> None:
        # SPEC §3: a CIDR typo must not surface as a bare 404 that VT-trained
        # analysts read as "IP unknown".
        raise HTTPException(status_code=400, detail="not a single IP address")

    return app
