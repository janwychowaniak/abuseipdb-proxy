"""The error contract (SPEC D4, D11): every upstream row, with `upstream` and
Retry-After, the 200 contract, and the unexpected failure."""

import pytest
import requests
from conftest import CHECK, captured
from fastapi.testclient import TestClient

from abuseipdb_proxy.app import create_app

MSG = "never-in-an-error-body"
LOOKUP = {"artifact": "8.8.8.8", "msg": MSG}
HTML = "<html><body><h1>502 Bad Gateway</h1></body></html>"


def error_of(resp) -> dict:
    """The answer's error object; the body holds nothing else, and never the msg sent."""
    body = resp.json()
    assert list(body) == ["error"]
    assert MSG not in resp.text
    return body["error"]


def upstream_detail(capture: str) -> str:
    return captured(capture)["body"]["errors"][0]["detail"]


def test_upstream_401_is_502_upstream_auth(client, fake_upstream):
    fake_upstream.arm_capture("error-bad-key")
    resp = client.post(CHECK, json=LOOKUP)
    assert resp.status_code == 502
    assert error_of(resp) == {
        "code": "UPSTREAM_AUTH",
        "message": "upstream refused this service's API key — check ABUSEIPDB_API_KEY",
        "upstream": {"status": 401, "message": upstream_detail("error-bad-key")},
    }


def test_upstream_403_is_502_upstream_auth(client, fake_upstream):
    fake_upstream.arm(403, body={"errors": [{"detail": "Forbidden.", "status": 403}]})
    resp = client.post(CHECK, json=LOOKUP)
    assert resp.status_code == 502
    error = error_of(resp)
    assert error["code"] == "UPSTREAM_AUTH"
    assert error["upstream"] == {"status": 403, "message": "Forbidden."}


def test_upstream_429_is_upstream_quota_with_retry_after(client, fake_upstream):
    fake_upstream.arm_capture("error-quota-429.RECONSTRUCTED")
    resp = client.post(CHECK, json=LOOKUP)
    assert resp.status_code == 429
    assert error_of(resp) == {
        "code": "UPSTREAM_QUOTA",
        "message": "upstream daily rate limit exceeded",
        "upstream": {"status": 429, "message": upstream_detail("error-quota-429.RECONSTRUCTED")},
    }
    assert resp.headers["Retry-After"] == "28800"


def test_degraded_429_html_body_no_retry_after(client, fake_upstream):
    # D4 (audit): CDN-era 429s can be HTML with no Retry-After; status alone decides.
    fake_upstream.arm(429, text=HTML)
    resp = client.post(CHECK, json=LOOKUP)
    assert resp.status_code == 429
    assert error_of(resp) == {
        "code": "UPSTREAM_QUOTA",
        "message": "upstream daily rate limit exceeded",
    }
    assert "Retry-After" not in resp.headers  # omitted, never fabricated


def test_upstream_504_is_upstream_timeout_with_upstream(client, fake_upstream):
    # The upstream's own deadline: 504, and `upstream` says the upstream noticed it.
    fake_upstream.arm(504, body={"errors": [{"detail": "Gateway timeout.", "status": 504}]})
    resp = client.post(CHECK, json=LOOKUP)
    assert resp.status_code == 504
    assert error_of(resp) == {
        "code": "UPSTREAM_TIMEOUT",
        "message": "upstream reported a timeout (HTTP 504)",
        "upstream": {"status": 504, "message": "Gateway timeout."},
    }


@pytest.mark.parametrize(
    ("exc", "message"),
    [
        (requests.exceptions.ConnectTimeout("boom"), "no response within the configured timeout"),
        (requests.exceptions.ReadTimeout("boom"), "no response within the configured timeout"),
        (requests.exceptions.ConnectionError("refused"), "upstream unreachable (ConnectionError)"),
        (requests.exceptions.SSLError("bad cert"), "upstream unreachable (SSLError)"),
    ],
    ids=["connect timeout", "read timeout", "connection error", "TLS"],
)
def test_no_answer_is_504_upstream_timeout(client, fake_upstream, exc, message):
    fake_upstream.arm_exc(exc)
    resp = client.post(CHECK, json=LOOKUP)
    assert resp.status_code == 504
    assert error_of(resp) == {"code": "UPSTREAM_TIMEOUT", "message": message}


@pytest.mark.parametrize(
    ("status", "body", "text"),
    [
        (500, {"errors": [{"detail": "boom", "status": 500}]}, None),
        (503, None, HTML),
        (502, None, None),
        (422, None, None),
        (404, {"errors": [{"detail": "Not found.", "status": 404}]}, None),
        (204, None, None),
    ],
    ids=["500 JSON", "503 HTML", "502 empty", "422 empty", "404 JSON", "204"],
)
def test_any_other_status_is_502_upstream_error(client, fake_upstream, status, body, text):
    fake_upstream.arm(status, body=body, text=text)
    resp = client.post(CHECK, json=LOOKUP)
    assert resp.status_code == 502
    error = error_of(resp)
    assert error["code"] == "UPSTREAM_ERROR"
    assert error["message"] == f"upstream returned HTTP {status}"
    if body is None:
        assert "upstream" not in error  # never a partial one
    else:
        assert error["upstream"] == {"status": status, "message": body["errors"][0]["detail"]}


def test_upstream_422_after_local_validation_is_502(client, fake_upstream):
    # Post-D3 a 422 means validator/upstream disagreement — a bug surface, not passthrough.
    fake_upstream.arm_capture("invalid-string")
    resp = client.post(CHECK, json=LOOKUP)
    assert resp.status_code == 502
    assert error_of(resp) == {
        "code": "UPSTREAM_ERROR",
        "message": "upstream returned HTTP 422",
        "upstream": {"status": 422, "message": upstream_detail("invalid-string")},
    }


@pytest.mark.parametrize(
    "body",
    [
        {"errors": []},
        {"errors": {}},
        {"errors": ["boom"]},
        {"errors": [{"status": 500}]},
        {"errors": [{"detail": 5}]},
        {"error": {"code": "InternalError", "message": "boom"}},
        ["boom"],
        "boom",
    ],
    ids=["no error", "errors not a list", "not an object", "no detail", "detail not text",
         "another API's shape", "a list", "a string"],
)  # fmt: skip
def test_only_the_upstreams_error_object_gives_upstream(client, fake_upstream, body):
    fake_upstream.arm(500, body=body)
    error = error_of(client.post(CHECK, json=LOOKUP))
    assert error == {"code": "UPSTREAM_ERROR", "message": "upstream returned HTTP 500"}


# --- the 200 contract: the fields D2 reads ---------------------------------------------


@pytest.mark.parametrize(
    ("body", "text"),
    [
        (None, "<html>surprise</html>"),
        ({"unexpected": True}, None),
        ({"data": []}, None),
        ({"data": None}, None),
        ({"data": {"abuseConfidenceScore": "high"}}, None),
        ({"data": {"abuseConfidenceScore": True}}, None),
        ({"data": {"abuseConfidenceScore": 30.0}}, None),
        ({"data": {"abuseConfidenceScore": 5, "totalReports": None}}, None),
        ({"data": {"abuseConfidenceScore": 5, "totalReports": "3"}}, None),
        ({"data": {"abuseConfidenceScore": 5, "totalReports": True}}, None),
    ],
    ids=["not JSON", "no data", "data a list", "data null", "score text", "score true",
         "score a float", "totalReports null", "totalReports text", "totalReports true"],
)  # fmt: skip
def test_an_unreadable_200_is_502_upstream_schema(client, fake_upstream, body, text):
    fake_upstream.arm(200, body=body, text=text)
    resp = client.post(CHECK, json=LOOKUP)
    assert resp.status_code == 502
    assert error_of(resp) == {
        "code": "UPSTREAM_SCHEMA",
        "message": "upstream response shape not recognized",
    }


def test_an_unexpected_failure_is_500_internal(settings, fake_upstream):
    fake_upstream.arm_exc(RuntimeError("boom"))  # not a requests failure: a bug of ours
    client = TestClient(create_app(settings), raise_server_exceptions=False)
    resp = client.post(CHECK, json=LOOKUP)
    assert resp.status_code == 500
    assert error_of(resp) == {"code": "INTERNAL", "message": "internal error"}
