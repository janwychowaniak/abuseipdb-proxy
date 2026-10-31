"""Shared fixtures: offline enforcement, capture-backed fake upstream, and the TLS
upstreams on loopback that the trust tests use (SPEC §6)."""

import ipaddress
import json
import os
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import requests
import trustme
from fastapi.testclient import TestClient

from abuseipdb_proxy import upstream
from abuseipdb_proxy.app import create_app
from abuseipdb_proxy.settings import Settings

CAPTURES = Path(__file__).resolve().parents[1] / "docs" / "research" / "captures"


def admitted_by_guard(address: object) -> bool:
    """A numeric loopback address, in any shape connect() receives (SPEC §6).

    AF_INET passes (host, port), AF_INET6 the same with flowinfo and scope_id
    optionally appended; an AF_UNIX path (str or bytes) is never admitted. A name
    such as "localhost" is not numeric and is refused: urllib3 resolves names
    itself before it connects, so the TLS tests never pass one.
    """
    if not (isinstance(address, tuple) and len(address) >= 2 and isinstance(address[0], str)):
        return False
    try:
        return ipaddress.ip_address(address[0]).is_loopback
    except ValueError:
        return False


@pytest.fixture(autouse=True)
def _no_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """SPEC §6: a single mock miss must never make a real network call.

    Tests marked `loopback` may connect to numeric loopback addresses, and
    nowhere else; every other test may connect nowhere.
    """
    if request.node.get_closest_marker("live"):
        return
    loopback = request.node.get_closest_marker("loopback") is not None
    connect = socket.socket.connect

    def _guarded(self: socket.socket, address: object) -> None:
        if loopback and admitted_by_guard(address):
            return connect(self, address)
        raise AssertionError("offline test attempted a real network connection (SPEC §6)")

    monkeypatch.setattr(socket.socket, "connect", _guarded)


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
        abuseipdb_base_url="https://api.abuseipdb.com/api/v2",
        ca_file=None,
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
        self.mounted: dict[str, requests.adapters.BaseAdapter] = {}

    def arm_capture(self, name: str) -> None:
        self.response = response_from_capture(name)

    def arm(self, *args: object, **kwargs: object) -> None:
        self.response = make_response(*args, **kwargs)  # type: ignore[arg-type]

    def arm_exc(self, exc: Exception) -> None:
        self.exc = exc

    def mount(self, prefix: str, adapter: requests.adapters.BaseAdapter) -> None:
        # create_app mounts the upstream TLS context in every configuration (SPEC D9)
        self.mounted[prefix] = adapter

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


# --- TLS upstreams on loopback (CA_FILE) -----------------------------------------------
#
# Certificates are generated per run (trustme) and never committed. The TLS upstream and
# the CONNECT proxy listen on loopback only, the upstream answers with a frozen capture,
# and every request goes through the client a deployment builds: the module-level
# session, with the adapter create_app mounts on it.

API_KEY = "test-key-never-printed"
NO_UPSTREAM = "https://upstream.invalid/api/v2"  # for tests that make no lookup
LOOKUP = "/check/87.98.154.146"  # the address midscore-default.json answers for
CAPTURE = json.loads((CAPTURES / "midscore-default.json").read_text())["response"]
# what the client takes from the environment: proxies, and a bundle replacing certifi's
CLIENT_ENV = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
)
# the service's own configuration, kept out of a subprocess unless a test sets it
SERVICE_ENV = (
    "ABUSEIPDB_API_KEY",
    "SCORE_THRESHOLD",
    "MAX_AGE_DAYS",
    "UPSTREAM_TIMEOUT_S",
    "ABUSEIPDB_BASE_URL",
    "CA_FILE",
)


@pytest.fixture
def isolated_client(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in CLIENT_ENV:
        monkeypatch.delenv(name, raising=False)
    # The production session lives as long as the process; a test must not
    # inherit the adapter another test's create_app mounted on it.
    monkeypatch.setattr(upstream, "_session", requests.Session())


class _Capture(BaseHTTPRequestHandler):
    """Answers every GET with the frozen capture, as AbuseIPDB answered it."""

    def do_GET(self) -> None:
        body = json.dumps(CAPTURE["body"]).encode()
        self.send_response(CAPTURE["status"])
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # keep the test output clean
        pass


@contextmanager
def tls_upstream(leaf: trustme.LeafCert) -> Iterator[str]:
    """An HTTPS upstream on loopback presenting `leaf`; yields its base URL."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    leaf.configure_cert(context)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Capture)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"https://127.0.0.1:{server.server_address[1]}/api/v2"
    finally:
        server.shutdown()
        server.server_close()


def _pipe(source: socket.socket, sink: socket.socket) -> None:
    with suppress(OSError):
        while data := source.recv(65536):
            sink.sendall(data)
    with suppress(OSError):
        sink.shutdown(socket.SHUT_WR)


class _ConnectRelay(socketserver.BaseRequestHandler):
    """A plain http:// egress proxy: CONNECT, then bytes both ways, unread."""

    def handle(self) -> None:
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            head += chunk
        method, target, _ = head.split(b"\r\n", 1)[0].decode().split(" ", 2)
        self.server.seen.append(f"{method} {target}")
        host, port = target.rsplit(":", 1)
        with socket.create_connection((host, int(port)), timeout=10) as far:
            self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            back = threading.Thread(target=_pipe, args=(far, self.request), daemon=True)
            back.start()
            _pipe(self.request, far)
            back.join(timeout=10)


class _ConnectProxy(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _ConnectRelay)
        self.seen: list[str] = []


@contextmanager
def connect_proxy() -> Iterator[tuple[str, list[str]]]:
    """A CONNECT proxy on loopback; yields its URL and the request lines it saw."""
    server = _ConnectProxy()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", server.seen
    finally:
        server.shutdown()
        server.server_close()


def leaf_from(ca: trustme.CA) -> trustme.LeafCert:
    return ca.issue_cert("127.0.0.1")


def pem_file(path: Path, *blobs: trustme.Blob) -> str:
    path.write_bytes(b"".join(blob.bytes() for blob in blobs))
    return str(path)


def service(base_url: str, ca_file: str | None = None) -> TestClient:
    """The service as a deployment builds it: settings in, the real session out."""
    settings = Settings(
        _env_file=None,
        abuseipdb_api_key=API_KEY,
        score_threshold=30,
        max_age_days=30,
        upstream_timeout_s=5,
        abuseipdb_base_url=base_url,
        ca_file=ca_file,
    )
    return TestClient(create_app(settings))


def assert_reached(client: TestClient) -> None:
    response = client.get(LOOKUP)
    assert response.status_code == 200
    assert response.json()["verdict"] == {"score": 30, "thresh_gte": True}  # the capture's


def assert_refused(client: TestClient) -> str:
    """The lookup fails on the transport-error path; returns its detail."""
    response = client.get(LOOKUP)
    assert response.status_code == 504  # the transport-error path, as for any failed TLS
    detail = response.json()["detail"]
    assert detail.startswith("upstream-timeout:")
    return detail


def run_entrypoint(cwd: Path, **env: str) -> subprocess.CompletedProcess[str]:
    """The image's command, with only `env` of the service's own configuration."""
    inherited = {name: value for name, value in os.environ.items() if name not in SERVICE_ENV}
    return subprocess.run(
        [sys.executable, "-m", "uvicorn", "--factory", "abuseipdb_proxy.app:create_app"],
        cwd=cwd,  # no .env here: only this environment reaches the settings
        env=inherited | env,
        capture_output=True,
        text=True,
        timeout=60,
    )
