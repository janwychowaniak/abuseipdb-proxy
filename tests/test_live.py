"""Optional live smoke (SPEC §6): shape and invariants only — upstream data drifts."""

import os

import pytest
from fastapi.testclient import TestClient

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("ABUSEIPDB_LIVE_TESTS") != "1",
        reason="live tests run only when ABUSEIPDB_LIVE_TESTS equals the literal string '1'",
    ),
]


def test_live_check_shape():
    from abuseipdb_proxy.app import create_app  # settings from the real .env

    client = TestClient(create_app())
    resp = client.post("/v1/check", json={"artifact": "8.8.8.8", "msg": "live"})
    assert resp.status_code == 200
    body = resp.json()
    assert list(body) == ["query", "known", "verdict", "report"]
    query = body["query"]
    assert list(query) == ["artifact", "type", "threshold", "max_age_days", "verbose", "msg"]
    assert (query["artifact"], query["type"], query["msg"]) == ("8.8.8.8", "ip", "live")
    assert isinstance(body["known"], bool)
    assert 0 <= body["verdict"]["score"] <= 100
    assert isinstance(body["verdict"]["thresh_gte"], bool)
    assert body["report"]["ipAddress"] == "8.8.8.8"


def test_live_health():
    from abuseipdb_proxy.app import create_app

    body = TestClient(create_app()).get("/v1/health").json()
    assert body["status"] == "ok"
    assert set(body) == {"status", "name", "version", "extra_ca", "x509_strict"}
