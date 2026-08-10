"""Shared fixtures: offline enforcement, capture-backed fake upstream (SPEC §6)."""

import json
import socket
from pathlib import Path

import pytest
import requests
from fastapi.testclient import TestClient

from abuseipdb_proxy import upstream
from abuseipdb_proxy.app import create_app
from abuseipdb_proxy.settings import Settings

CAPTURES = Path(__file__).resolve().parents[1] / "docs" / "research" / "captures"


@pytest.fixture(autouse=True)
def _no_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """SPEC §6: a single mock miss must never make a real network call."""
    if request.node.get_closest_marker("live"):
        return

    def _blocked(self: socket.socket, *args: object) -> None:
        raise AssertionError("offline test attempted a real network connection (SPEC §6)")

    monkeypatch.setattr(socket.socket, "connect", _blocked)


@pytest.fixture
def settings() -> Settings:
    # Never reads the repository .env (SPEC §6): explicit kwargs beat every
    # pydantic-settings source, and the env file is disabled outright.
    return Settings(
        _env_file=None,
        abuseipdb_api_key="test-key-not-real",
        score_threshold=30,
        max_age_days=30,
        upstream_timeout_s=5,
    )


def make_response(
    status: int,
    body: object | None = None,
    headers: dict[str, str] | None = None,
    text: str | None = None,
) -> requests.Response:
    resp = requests.Response()
    resp.status_code = status
    if body is not None:
        resp._content = json.dumps(body).encode()
        resp.headers["Content-Type"] = "application/json"
    elif text is not None:
        resp._content = text.encode()
        resp.headers["Content-Type"] = "text/html"
    else:
        resp._content = b""
    if headers:
        resp.headers.update(headers)
    return resp


def response_from_capture(name: str) -> requests.Response:
    doc = json.loads((CAPTURES / f"{name}.json").read_text())
    captured = doc["response"]
    return make_response(captured["status"], body=captured["body"], headers=captured.get("headers"))


class FakeUpstream:
    """Stands in for upstream._session; records calls, replays one response."""

    def __init__(self) -> None:
        self.response: requests.Response | None = None
        self.exc: Exception | None = None
        self.calls: list[dict[str, object]] = []

    def arm_capture(self, name: str) -> None:
        self.response = response_from_capture(name)

    def arm(self, *args: object, **kwargs: object) -> None:
        self.response = make_response(*args, **kwargs)  # type: ignore[arg-type]

    def arm_exc(self, exc: Exception) -> None:
        self.exc = exc

    def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        timeout: object = None,
    ) -> requests.Response:
        self.calls.append({"url": url, "headers": headers, "params": params, "timeout": timeout})
        if self.exc is not None:
            raise self.exc
        assert self.response is not None, "FakeUpstream used before arming"
        return self.response


@pytest.fixture
def fake_upstream(monkeypatch: pytest.MonkeyPatch) -> FakeUpstream:
    fake = FakeUpstream()
    monkeypatch.setattr(upstream, "_session", fake)
    return fake


@pytest.fixture
def client(settings: Settings, fake_upstream: FakeUpstream) -> TestClient:
    return TestClient(create_app(settings))
