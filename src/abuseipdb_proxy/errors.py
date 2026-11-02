"""The error contract (SPEC D4, D11; docs/ENVELOPE.md §5): the codes, the error body,
and the mapping of the upstream's answers onto them."""

from collections.abc import Sequence
from typing import Any

import requests
from fastapi.responses import JSONResponse

from abuseipdb_proxy import tls

VALIDATION_ERROR = "VALIDATION_ERROR"
INVALID_ARTIFACT = "INVALID_ARTIFACT"
UPSTREAM_AUTH = "UPSTREAM_AUTH"
UPSTREAM_QUOTA = "UPSTREAM_QUOTA"
UPSTREAM_TIMEOUT = "UPSTREAM_TIMEOUT"
UPSTREAM_ERROR = "UPSTREAM_ERROR"
UPSTREAM_SCHEMA = "UPSTREAM_SCHEMA"
NOT_FOUND = "NOT_FOUND"
METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
INTERNAL = "INTERNAL"


class ApiError(Exception):
    """One non-2xx answer: its status, code and message, the upstream's error object
    when it parsed, and the headers to pass on."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        upstream: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.upstream = upstream
        self.headers = headers


def error_response(error: ApiError) -> JSONResponse:
    """`{"error": {code, message, upstream?}}`, the body of every non-2xx answer."""
    body: dict[str, object] = {"code": error.code, "message": error.message}
    if error.upstream is not None:
        body["upstream"] = error.upstream
    return JSONResponse(
        status_code=error.status_code, content={"error": body}, headers=error.headers
    )


def validation_message(errors: Sequence[Any]) -> str:
    """`<field>: <reason>` per failure, joined by `; `; the body as a whole is `body`."""
    parts = []
    for err in errors:
        loc = tuple(err.get("loc", ()))
        if err.get("type") == "json_invalid":  # FastAPI puts the decoder's position last
            parts.append(f"body: JSON decode error at position {loc[-1]}")
            continue
        field = ".".join(str(piece) for piece in loc if piece != "body")
        parts.append(f"{field or 'body'}: {err.get('msg')}")
    return "; ".join(parts)


def upstream_error_object(resp: requests.Response) -> dict[str, object] | None:
    """`upstream`: the upstream's HTTP status and its `errors[0].detail`, when the body
    parses as its JSON API error object; None for any other body, never a part (D4)."""
    try:
        body = resp.json()
    except ValueError:
        return None
    errors = body.get("errors") if isinstance(body, dict) else None
    first = errors[0] if isinstance(errors, list) and errors else None
    detail = first.get("detail") if isinstance(first, dict) else None
    if not isinstance(detail, str):
        return None
    return {"status": resp.status_code, "message": detail}


def status_error(resp: requests.Response) -> ApiError:
    """A non-200 answer of the upstream as the error it maps to; the status alone picks
    the code, the body only feeds `upstream` (D4)."""
    status = resp.status_code
    upstream = upstream_error_object(resp)
    if status in (401, 403):  # the service's misconfiguration, not the caller's
        message = "upstream refused this service's API key — check ABUSEIPDB_API_KEY"
        return ApiError(502, UPSTREAM_AUTH, message, upstream)
    if status == 429:
        # Retry-After passed through when present, never invented.
        retry_after = resp.headers.get("Retry-After")
        headers = {"Retry-After": retry_after} if retry_after else None
        message = "upstream daily rate limit exceeded"
        return ApiError(429, UPSTREAM_QUOTA, message, upstream, headers)
    if status == 504:  # the upstream's own deadline counts as a timeout
        return ApiError(504, UPSTREAM_TIMEOUT, "upstream reported a timeout (HTTP 504)", upstream)
    return ApiError(502, UPSTREAM_ERROR, f"upstream returned HTTP {status}", upstream)


def transport_error(exc: requests.exceptions.RequestException, strict: bool) -> ApiError:
    """No answer from the upstream, a failed TLS verification included: 504. While the
    strict X.509 checks are on, a failure only they cause names its reason (D10)."""
    if isinstance(exc, requests.exceptions.Timeout):
        message = "no response within the configured timeout"
    else:
        message = f"upstream unreachable ({type(exc).__name__})"
    if strict:
        message += tls.strict_hint(exc)
    return ApiError(504, UPSTREAM_TIMEOUT, message)


def read_data(resp: requests.Response) -> tuple[dict[str, Any], int]:
    """The `data` object of a 200 and its score, when the fields D2 reads are readable:
    the score an integer, `totalReports` one when present. UPSTREAM_SCHEMA otherwise."""
    try:
        body = resp.json()
    except ValueError:
        raise _unreadable() from None
    data = body.get("data") if isinstance(body, dict) else None
    if not isinstance(data, dict):
        raise _unreadable()
    score = data.get("abuseConfidenceScore")
    if not _is_integer(score):
        raise _unreadable()
    if "totalReports" in data and not _is_integer(data["totalReports"]):
        raise _unreadable()
    return data, score


def _is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)  # JSON true is no integer


def _unreadable() -> ApiError:
    return ApiError(502, UPSTREAM_SCHEMA, "upstream response shape not recognized")
