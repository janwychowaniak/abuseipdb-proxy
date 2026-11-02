"""Routing (SPEC §3, D11): enveloped 404 and 405, no trailing-slash redirects, and the
OpenAPI documents at FastAPI's defaults."""

from importlib.metadata import version

import pytest
from conftest import CHECK
from fastapi.testclient import TestClient

from abuseipdb_proxy.app import create_app
from abuseipdb_proxy.settings import Settings


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/check/8.8.8.8"),
        ("GET", "/health"),
        ("POST", "/v1/check/"),
        ("GET", "/v1/health/"),
        ("GET", "/v1/nope"),
        ("GET", "/"),
        ("GET", "/docs/"),
    ],
    ids=["0.3.0's lookup", "0.3.0's health", "a trailing slash", "a trailing slash on health",
         "unknown", "root", "a trailing slash on the documents"],
)  # fmt: skip
def test_an_unknown_path_is_404_not_found(client, fake_upstream, method, path):
    # The client follows redirects, so a trailing-slash redirect would not end in a 404.
    json = {"artifact": "8.8.8.8"} if method == "POST" else None
    resp = client.request(method, path, json=json)
    assert resp.status_code == 404
    assert resp.json() == {"error": {"code": "NOT_FOUND", "message": "unknown path"}}
    assert fake_upstream.calls == []


@pytest.mark.parametrize(
    ("method", "path", "allow"),
    [("GET", CHECK, "POST"), ("PUT", CHECK, "POST"), ("POST", "/v1/health", "GET")],
)
def test_a_wrong_method_is_405_with_allow(client, method, path, allow):
    resp = client.request(method, path)
    assert resp.status_code == 405
    assert resp.json() == {
        "error": {"code": "METHOD_NOT_ALLOWED", "message": "method not allowed for this path"}
    }
    assert resp.headers["Allow"] == allow  # RFC 9110 requires it on a 405


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"])
def test_the_openapi_documents_are_served(client, path):
    assert client.get(path).status_code == 200


def test_the_document_names_the_package_version_and_the_two_endpoints(client):
    doc = client.get("/openapi.json").json()
    assert doc["info"] == {"title": "abuseipdb-proxy", "version": version("abuseipdb-proxy")}
    assert {path: sorted(item) for path, item in doc["paths"].items()} == {
        CHECK: ["post"],
        "/v1/health": ["get"],
    }


def test_the_document_shows_the_configured_defaults():
    custom = Settings(
        _env_file=None, abuseipdb_api_key="test-key-not-real", score_threshold=77, max_age_days=90
    )
    doc = TestClient(create_app(custom)).get("/openapi.json").json()
    properties = doc["components"]["schemas"]["CheckRequest"]["properties"]
    assert properties["threshold"]["default"] == 77
    assert properties["max_age_days"]["default"] == 90
