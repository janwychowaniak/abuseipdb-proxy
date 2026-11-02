"""The envelope and the error body through the client a deployment builds (SPEC §6):
the real session with the adapter create_app mounts, against a TLS upstream on
loopback that the file in CA_FILE vouches for. The other tests fake the session."""

import json

import pytest
import trustme
from conftest import (
    CAPTURE,
    CAPTURE_ANSWER,
    CHECK,
    LOOKUP,
    Answer,
    captured,
    leaf_from,
    pem_file,
    service,
    tls_upstream,
)

pytestmark = [pytest.mark.loopback, pytest.mark.usefixtures("isolated_client")]


def through_the_session(tmp_path, answer: Answer = CAPTURE_ANSWER):
    ca = trustme.CA()
    with tls_upstream(leaf_from(ca), answer) as url:
        return service(url, pem_file(tmp_path / "ca.pem", ca.cert_pem)).post(CHECK, json=LOOKUP)


def test_a_known_lookup_answers_the_envelope(tmp_path):
    resp = through_the_session(tmp_path)
    assert resp.status_code == 200
    body = resp.json()
    assert list(body) == ["query", "known", "verdict", "report"]
    assert body["query"]["artifact"] == LOOKUP["artifact"]
    assert body["report"] == CAPTURE["body"]["data"]


def test_a_429_passes_upstream_and_retry_after_through(tmp_path):
    capture = captured("error-quota-429.RECONSTRUCTED")
    resp = through_the_session(
        tmp_path, (capture["status"], capture["headers"], json.dumps(capture["body"]).encode())
    )
    assert resp.status_code == 429
    assert resp.headers["Retry-After"] == "28800"
    assert resp.json() == {
        "error": {
            "code": "UPSTREAM_QUOTA",
            "message": "upstream daily rate limit exceeded",
            "upstream": {"status": 429, "message": capture["body"]["errors"][0]["detail"]},
        }
    }


def test_an_html_error_gives_no_upstream(tmp_path):
    resp = through_the_session(tmp_path, (503, {"Content-Type": "text/html"}, b"<html>down</html>"))
    assert resp.status_code == 502
    assert resp.json() == {
        "error": {"code": "UPSTREAM_ERROR", "message": "upstream returned HTTP 503"}
    }
