"""D4 error mapping — every row, including the degraded 429."""

import requests


def test_upstream_401_maps_to_502_auth(client, fake_upstream):
    fake_upstream.arm_capture("error-bad-key")
    resp = client.get("/check/8.8.8.8")
    assert resp.status_code == 502
    assert resp.json()["detail"].startswith("upstream-auth:")
    assert "ABUSEIPDB_API_KEY" in resp.json()["detail"]


def test_upstream_429_passes_through(client, fake_upstream):
    fake_upstream.arm_capture("error-quota-429.RECONSTRUCTED")
    resp = client.get("/check/8.8.8.8")
    assert resp.status_code == 429
    assert "rate limit" in resp.json()["detail"].lower()
    assert resp.headers["Retry-After"] == "28800"


def test_degraded_429_html_body_no_retry_after(client, fake_upstream):
    # D4 (audit): CDN-era 429s can be HTML with no Retry-After; status alone decides.
    fake_upstream.arm(429, text="<html><body>Too Many Requests</body></html>")
    resp = client.get("/check/8.8.8.8")
    assert resp.status_code == 429
    assert resp.json()["detail"] == "upstream daily rate limit exceeded"
    assert "Retry-After" not in resp.headers  # omitted, never fabricated


def test_timeout_maps_to_504(client, fake_upstream):
    fake_upstream.arm_exc(requests.exceptions.ConnectTimeout("boom"))
    resp = client.get("/check/8.8.8.8")
    assert resp.status_code == 504
    assert resp.json()["detail"].startswith("upstream-timeout:")


def test_connection_error_maps_to_504(client, fake_upstream):
    fake_upstream.arm_exc(requests.exceptions.ConnectionError("refused"))
    resp = client.get("/check/8.8.8.8")
    assert resp.status_code == 504
    assert resp.json()["detail"].startswith("upstream-timeout:")


def test_unexpected_status_maps_to_502(client, fake_upstream):
    fake_upstream.arm(500, body={"errors": [{"detail": "boom", "status": 500}]})
    resp = client.get("/check/8.8.8.8")
    assert resp.status_code == 502
    assert resp.json()["detail"].startswith("upstream-unexpected:")
    assert "500" in resp.json()["detail"]


def test_upstream_422_after_local_validation_is_502(client, fake_upstream):
    # Post-D3 a 422 means validator/upstream disagreement — a bug surface, not passthrough.
    fake_upstream.arm_capture("invalid-string")
    resp = client.get("/check/8.8.8.8")
    assert resp.status_code == 502
    assert resp.json()["detail"].startswith("upstream-unexpected:")


def test_200_with_non_json_body_is_502(client, fake_upstream):
    fake_upstream.arm(200, text="<html>surprise</html>")
    resp = client.get("/check/8.8.8.8")
    assert resp.status_code == 502
    assert resp.json()["detail"] == "upstream-unexpected: response shape not recognized"


def test_200_with_missing_data_is_502(client, fake_upstream):
    fake_upstream.arm(200, body={"unexpected": True})
    assert client.get("/check/8.8.8.8").status_code == 502


def test_200_with_non_int_score_is_502(client, fake_upstream):
    fake_upstream.arm(200, body={"data": {"abuseConfidenceScore": "high"}})
    assert client.get("/check/8.8.8.8").status_code == 502
