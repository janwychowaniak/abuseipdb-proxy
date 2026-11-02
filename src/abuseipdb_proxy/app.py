"""FastAPI application — every endpoint and handler is a plain `def` (SPEC D7).

Run: uvicorn --factory abuseipdb_proxy.app:create_app
The factory instantiates Settings eagerly, so a misconfigured process dies
before the server binds (SPEC §4); X509_STRICT and then CA_FILE are checked
right after (D10, D9). The API is the family's envelope (D11, docs/ENVELOPE.md).
"""

import logging
import time
from importlib.metadata import metadata

import requests
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from abuseipdb_proxy import ca, tls, upstream
from abuseipdb_proxy.errors import (
    INTERNAL,
    INVALID_ARTIFACT,
    METHOD_NOT_ALLOWED,
    NOT_FOUND,
    VALIDATION_ERROR,
    ApiError,
    error_response,
    read_data,
    status_error,
    transport_error,
    validation_message,
)
from abuseipdb_proxy.ipcheck import InvalidIPError, validate_ip
from abuseipdb_proxy.jsonlog import configure_logging
from abuseipdb_proxy.settings import Settings

logger = logging.getLogger("abuseipdb_proxy")

CHECK_PATH = "/v1/check"
_RATELIMIT_WARN_BELOW = 50  # SPEC §7: the log stream is the sole quota signal
# The check line's keys after event, our_status and code, in this order (SPEC §7).
_LINE_KEYS = (
    "artifact",
    "ip",
    "threshold",
    "max_age_days",
    "verbose",
    "msg",
    "upstream_status",
    "upstream_ms",
    "score",
    "known",
    "thresh_gte",
    "ratelimit_remaining",
)


def _log_check(our_status: int, facts: dict[str, object], error: ApiError | None = None) -> None:
    """The one line per answer of POST /v1/check (SPEC §7).

    Its text, the formatter's `message`, is the error message on a non-2xx answer and
    "check" on a 2xx. `artifact` is always there, null when the body did not parse.
    """
    line: dict[str, object] = {"event": "check", "our_status": our_status}
    if error is not None:
        line["code"] = error.code
    line["artifact"] = facts.get("artifact")
    line.update((key, facts[key]) for key in _LINE_KEYS[1:] if key in facts)
    if error is not None and error.upstream is not None:
        line["upstream"] = error.upstream
    remaining = facts.get("ratelimit_remaining")
    low = isinstance(remaining, int) and remaining < _RATELIMIT_WARN_BELOW
    # under `fields`, which the formatter flattens: `msg` is a reserved LogRecord attribute
    logger.log(
        logging.WARNING if low else logging.INFO,
        "check" if error is None else error.message,
        extra={"fields": line},
    )


def _remaining(resp: requests.Response) -> int | None:
    raw = resp.headers.get("X-RateLimit-Remaining", "")
    return int(raw) if raw.isdigit() else None


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


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
    # SPEC §3: the OpenAPI documents at FastAPI's defaults; a trailing slash is an
    # unknown path, never a redirect (D11).
    app = FastAPI(title="abuseipdb-proxy", version=version, redirect_slashes=False)

    class CheckRequest(BaseModel):
        """The body of POST /v1/check (SPEC §3, D11): strict JSON types, unknown fields
        refused, the defaults this process is configured with (§4)."""

        model_config = ConfigDict(extra="forbid", strict=True)

        artifact: str = Field(min_length=1)
        threshold: int = Field(default=settings.score_threshold, ge=0, le=100)
        max_age_days: int = Field(default=settings.max_age_days, ge=1, le=365)
        verbose: bool = False
        msg: str | None = None

    def lookup(body: CheckRequest, facts: dict[str, object]) -> dict[str, object]:
        """D3, the CHECK call, D1/D2/D6 and the envelope, recording the line's facts."""
        try:
            parsed = validate_ip(body.artifact)
        except InvalidIPError as exc:
            raise ApiError(422, INVALID_ARTIFACT, str(exc)) from None
        canonical = str(parsed)  # D3.5: upstream always receives the canonical form
        facts["ip"] = canonical

        started = time.perf_counter()
        try:
            resp = upstream.check(settings, canonical, body.max_age_days, body.verbose)
        except requests.exceptions.RequestException as exc:
            facts["upstream_ms"] = _elapsed_ms(started)
            raise transport_error(exc, tls.is_strict(context)) from None
        facts["upstream_status"] = resp.status_code
        facts["upstream_ms"] = _elapsed_ms(started)
        remaining = _remaining(resp)
        if remaining is not None:
            facts["ratelimit_remaining"] = remaining
        if resp.status_code != 200:
            raise status_error(resp)
        data, score = read_data(resp)

        # D2: known = reported-in-window OR whitelisted OR non-zero score.
        known = data.get("totalReports", 0) > 0 or bool(data.get("isWhitelisted")) or score > 0
        thresh_gte = score >= body.threshold  # D6
        facts.update(score=score, known=known, thresh_gte=thresh_gte)
        return {
            "query": {
                "artifact": body.artifact,  # as sent: D3.5's form is in report.ipAddress
                "type": "ip",
                "threshold": body.threshold,
                "max_age_days": body.max_age_days,
                "verbose": body.verbose,
                "msg": body.msg,
            },
            "known": known,
            "verdict": {"score": score, "thresh_gte": thresh_gte},
            "report": data,
        }

    @app.post(CHECK_PATH)
    def check(body: CheckRequest) -> dict[str, object]:
        facts: dict[str, object] = {
            "artifact": body.artifact,
            "threshold": body.threshold,
            "max_age_days": body.max_age_days,
            "verbose": body.verbose,
        }
        if body.msg is not None:
            facts["msg"] = body.msg
        try:
            envelope = lookup(body, facts)
        except ApiError as exc:
            _log_check(exc.status_code, facts, exc)
            raise
        except Exception:
            # SPEC §7: the line still comes; the 500 handler answers INTERNAL.
            _log_check(500, facts, ApiError(500, INTERNAL, "internal error"))
            raise
        _log_check(200, facts)
        return envelope

    @app.get("/v1/health")
    def health() -> dict[str, object]:
        # Liveness only: no upstream call, no key use (SPEC §3). x509_strict is read
        # from the upstream context itself, not from the setting (D10).
        return {
            "status": "ok",
            "name": name,
            "version": version,
            "extra_ca": extra_ca,
            "x509_strict": tls.is_strict(context),
        }

    @app.exception_handler(ApiError)
    def _on_api_error(request: Request, exc: ApiError) -> JSONResponse:
        return error_response(exc)

    @app.exception_handler(RequestValidationError)
    def _on_invalid_body(request: Request, exc: RequestValidationError) -> JSONResponse:
        # SPEC §3: FastAPI's list-shaped 422 is not part of the contract.
        error = ApiError(422, VALIDATION_ERROR, validation_message(exc.errors()))
        if request.url.path == CHECK_PATH:  # the one endpoint with a body
            sent = exc.body if isinstance(exc.body, dict) else {}
            facts: dict[str, object] = {"artifact": sent.get("artifact")}
            if sent.get("msg") is not None:
                facts["msg"] = sent["msg"]
            _log_check(422, facts, error)
        return error_response(error)

    @app.exception_handler(StarletteHTTPException)
    def _on_routing_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        if exc.status_code == 404:
            error = ApiError(404, NOT_FOUND, "unknown path")
        elif exc.status_code == 405:
            # Starlette's Allow header stays: RFC 9110 requires it on a 405.
            error = ApiError(
                405, METHOD_NOT_ALLOWED, "method not allowed for this path", headers=exc.headers
            )
        else:
            error = ApiError(exc.status_code, INTERNAL, str(exc.detail), headers=exc.headers)
        line = {
            "event": "no_route",
            "our_status": error.status_code,
            "code": error.code,
            "method": request.method,
            "path": request.url.path,  # never the query string
        }
        logger.info(error.message, extra={"fields": line})
        return error_response(error)

    @app.exception_handler(Exception)
    def _on_unexpected(request: Request, exc: Exception) -> JSONResponse:
        # Starlette re-raises after answering, so uvicorn still logs the traceback.
        return error_response(ApiError(500, INTERNAL, "internal error"))

    return app
