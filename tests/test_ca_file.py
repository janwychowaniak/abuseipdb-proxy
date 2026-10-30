"""CA_FILE (SPEC D9): extra CA trust for TLS with the upstream, the startup
refusals, and what health and the log say about it.

Certificates are generated per run (trustme) and never committed. The TLS
upstream and the CONNECT proxy listen on loopback only, the upstream answers
with a frozen capture, and every request goes through the client a deployment
builds: the module-level session, with the adapter create_app mounts on it.
"""

import json
import os
import re
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import version
from pathlib import Path
from urllib.parse import urlsplit

import certifi
import pytest
import requests
import requests.adapters
import trustme
from conftest import CAPTURES
from fastapi.testclient import TestClient

from abuseipdb_proxy import upstream
from abuseipdb_proxy.app import create_app
from abuseipdb_proxy.ca import CAFileError, load_ca_file
from abuseipdb_proxy.settings import Settings

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


@pytest.fixture(autouse=True)
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


def assert_refused(client: TestClient) -> None:
    response = client.get(LOOKUP)
    assert response.status_code == 504  # the transport-error path, as for any failed TLS
    assert response.json()["detail"].startswith("upstream-timeout:")


def assert_union(ca_file: str, default: trustme.CA, extra: trustme.CA) -> None:
    """Servers under the default set and under the file are trusted; others are not."""
    for authority, trusted in ((default, True), (extra, True), (trustme.CA(), False)):
        with tls_upstream(leaf_from(authority)) as url:
            client = service(url, ca_file)
            if trusted:
                assert_reached(client)
            else:
                assert_refused(client)


def startup_lines(stdout: str) -> list[dict]:
    lines = [json.loads(line) for line in stdout.splitlines() if line.startswith("{")]
    return [line for line in lines if line.get("event") == "ca_file_loaded"]


def refusal(ca_file: str) -> str:
    """The line create_app ends the process with."""
    with pytest.raises(SystemExit) as exited:
        service(NO_UPSTREAM, ca_file)
    return str(exited.value.code)


# --- trust ---------------------------------------------------------------------------


@pytest.mark.loopback
def test_without_ca_file_an_unknown_authority_is_refused():
    with tls_upstream(leaf_from(trustme.CA())) as url:
        assert_refused(service(url))


@pytest.mark.loopback
def test_an_authority_from_ca_file_is_trusted(tmp_path):
    ca = trustme.CA()
    with tls_upstream(leaf_from(ca)) as url:
        assert_reached(service(url, pem_file(tmp_path / "ca.pem", ca.cert_pem)))


@pytest.mark.loopback
def test_an_authority_in_neither_set_is_still_refused(tmp_path):
    with tls_upstream(leaf_from(trustme.CA())) as url:
        assert_refused(service(url, pem_file(tmp_path / "ca.pem", trustme.CA().cert_pem)))


@pytest.mark.loopback
def test_ca_file_adds_to_the_default_set_on_the_deployment_path(tmp_path, monkeypatch):
    # verify=True and no bundle variable, as behind an egress proxy: the only thing
    # that carries the default set into the adapter's context is cert_verify setting
    # DEFAULT_CA_BUNDLE_PATH as ca_certs, and it reads that global at call time.
    default, extra = trustme.CA(), trustme.CA()
    bundle = pem_file(tmp_path / "default.pem", default.cert_pem)
    monkeypatch.setattr(requests.adapters, "DEFAULT_CA_BUNDLE_PATH", bundle)
    assert_union(pem_file(tmp_path / "ca.pem", extra.cert_pem), default, extra)


@pytest.mark.loopback
def test_ca_file_adds_to_the_bundle_requests_ca_bundle_selects(tmp_path, monkeypatch):
    default, extra = trustme.CA(), trustme.CA()
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", pem_file(tmp_path / "bundle.pem", default.cert_pem))
    assert_union(pem_file(tmp_path / "ca.pem", extra.cert_pem), default, extra)


@pytest.mark.loopback
def test_ca_file_is_trusted_inside_a_proxy_tunnel(tmp_path, monkeypatch):
    ca = trustme.CA()
    with tls_upstream(leaf_from(ca)) as url, connect_proxy() as (proxy_url, seen):
        monkeypatch.setenv("HTTPS_PROXY", proxy_url)
        assert_reached(service(url, pem_file(tmp_path / "ca.pem", ca.cert_pem)))
    assert seen == [f"CONNECT 127.0.0.1:{urlsplit(url).port}"]


@pytest.mark.loopback
def test_without_ca_file_the_tunnel_is_refused(monkeypatch):
    with tls_upstream(leaf_from(trustme.CA())) as url, connect_proxy() as (proxy_url, seen):
        monkeypatch.setenv("HTTPS_PROXY", proxy_url)
        assert_refused(service(url))
    assert seen == [f"CONNECT 127.0.0.1:{urlsplit(url).port}"]


# --- refusals --------------------------------------------------------------------------


def test_a_missing_file_refuses_the_start(tmp_path):
    path = str(tmp_path / "missing.pem")
    assert refusal(path) == f"CA_FILE: no such file: {path}"


def test_a_path_through_a_regular_file_is_a_missing_file(tmp_path):
    path = pem_file(tmp_path / "ca.pem", trustme.CA().cert_pem) + "/ca.pem"
    assert refusal(path) == f"CA_FILE: no such file: {path}"


def test_a_value_of_only_whitespace_is_a_path_not_an_empty_value():
    assert refusal("   ") == "CA_FILE: no such file:    "


def test_a_directory_refuses_the_start(tmp_path):
    assert refusal(str(tmp_path)) == f"CA_FILE: not a regular file: {tmp_path}"


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a file whatever its mode")
def test_an_unreadable_file_refuses_the_start(tmp_path):
    path = pem_file(tmp_path / "ca.pem", trustme.CA().cert_pem)
    Path(path).chmod(0)
    assert refusal(path) == f"CA_FILE: cannot be read (Permission denied): {path}"


def _corrupt(pem: bytes) -> bytes:
    lines = pem.splitlines(keepends=True)
    lines[1] = b"!!!!" + lines[1][4:]  # the first base64 line of the block
    return b"".join(lines)


NOT_LOADABLE: dict[str, Callable[[], bytes]] = {
    "empty": lambda: b"",
    "text only": lambda: b"no certificate here\n",
    "a private key only": lambda: leaf_from(trustme.CA()).private_key_pem.bytes(),
    "DER": lambda: ssl.PEM_cert_to_DER_cert(trustme.CA().cert_pem.bytes().decode()),
    "a corrupt block after a good one": lambda: (
        (pem := trustme.CA().cert_pem.bytes()) + _corrupt(pem)
    ),
}


@pytest.mark.parametrize("content", NOT_LOADABLE, ids=list(NOT_LOADABLE))
def test_a_file_without_a_loadable_certificate_refuses_the_start(tmp_path, content):
    path = tmp_path / "ca.pem"
    path.write_bytes(NOT_LOADABLE[content]())
    line = refusal(str(path))
    # the reason in between is the loader's own text, which is not pinned here
    assert line.startswith("CA_FILE: no certificate could be loaded (")
    assert line.endswith(f"): {path}")


# --- the real entrypoint ---------------------------------------------------------------


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


def test_the_refusal_is_the_only_output_of_the_real_entrypoint(tmp_path):
    missing = tmp_path / "missing.pem"
    result = run_entrypoint(tmp_path, ABUSEIPDB_API_KEY=API_KEY, CA_FILE=str(missing))
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == f"CA_FILE: no such file: {missing}\n"


def test_a_refusal_never_prints_the_api_key(tmp_path):
    path = tmp_path / "ca.pem"
    path.write_bytes(b"no certificate here\n")
    result = run_entrypoint(tmp_path, ABUSEIPDB_API_KEY=API_KEY, CA_FILE=str(path))
    assert result.returncode == 1
    assert result.stderr.startswith("CA_FILE: no certificate could be loaded (")
    assert API_KEY not in result.stdout + result.stderr


def test_a_missing_key_is_reported_before_ca_file(tmp_path):
    result = run_entrypoint(tmp_path, CA_FILE=str(tmp_path / "missing.pem"))
    assert result.returncode == 1
    assert result.stdout == ""
    # the key's own error, unchanged: pydantic's ValidationError naming the field
    assert "ValidationError" in result.stderr
    assert "abuseipdb_api_key" in result.stderr
    assert "CA_FILE:" not in result.stderr


# --- health and the startup line -------------------------------------------------------


def test_without_ca_file_health_says_false_and_no_line_is_logged(capsys):
    body = service(NO_UPSTREAM).get("/health").json()
    assert body == {
        "status": "ok",
        "name": "abuseipdb-proxy",
        "version": version("abuseipdb-proxy"),
        "extra_ca": False,
    }
    assert startup_lines(capsys.readouterr().out) == []


def test_an_empty_ca_file_is_absent(capsys):
    assert service(NO_UPSTREAM, "").get("/health").json()["extra_ca"] is False
    assert startup_lines(capsys.readouterr().out) == []


def test_with_ca_file_health_says_true_and_one_line_counts_the_certificates(tmp_path, capsys):
    path = pem_file(tmp_path / "ca.pem", trustme.CA().cert_pem, trustme.CA().cert_pem)
    assert service(NO_UPSTREAM, path).get("/health").json()["extra_ca"] is True
    [line] = startup_lines(capsys.readouterr().out)
    del line["ts"]
    assert line == {
        "level": "INFO",
        "logger": "abuseipdb_proxy",
        "message": "ca_file_loaded",
        "event": "ca_file_loaded",
        "path": path,
        "certificates": 2,
    }


# --- the count -------------------------------------------------------------------------


@pytest.mark.loopback
def test_a_leaf_alone_counts_and_pins_its_server(tmp_path, capsys):
    leaf = leaf_from(trustme.CA())
    path = pem_file(tmp_path / "leaf.pem", leaf.cert_chain_pems[0])
    with tls_upstream(leaf) as url:
        assert_reached(service(url, path))  # partial-chain verification: the leaf anchors itself
    [line] = startup_lines(capsys.readouterr().out)
    assert line["certificates"] == 1


def test_a_root_the_default_set_already_holds_still_counts(tmp_path, capsys):
    bundle = Path(certifi.where()).read_text()
    root = re.search(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----\n", bundle, re.S)
    assert root is not None
    path = tmp_path / "public-root.pem"
    path.write_text(root.group(0))
    service(NO_UPSTREAM, str(path))
    [line] = startup_lines(capsys.readouterr().out)
    assert line["certificates"] == 1


# --- reading: text outside the PEM blocks never decides ----------------------------------


def _byte_inside(pem: bytes) -> bytes:
    lines = pem.splitlines(keepends=True)
    lines[1] = lines[1][:10] + "é".encode() + lines[1][10:]
    return b"".join(lines)


READING: dict[str, tuple[Callable[[], bytes], int | None]] = {
    "UTF-8 text before the block": (
        lambda: "Issuer: Café Zürich\n".encode() + trustme.CA().cert_pem.bytes(),
        1,
    ),
    "a UTF-8 BOM before the block": (
        lambda: b"\xef\xbb\xbf" + trustme.CA().cert_pem.bytes(),
        1,
    ),
    "UTF-8 text between two blocks": (
        lambda: (
            trustme.CA().cert_pem.bytes() + "— next —\n".encode() + trustme.CA().cert_pem.bytes()
        ),
        2,
    ),
    "CRLF line endings": (
        lambda: trustme.CA().cert_pem.bytes().replace(b"\n", b"\r\n"),
        1,
    ),
    "a non-ASCII byte inside a block": (
        lambda: _byte_inside(trustme.CA().cert_pem.bytes()),
        None,
    ),
}


def count_by_service(path: Path) -> int | None:
    try:
        return load_ca_file(str(path))[1]
    except CAFileError:
        return None


def count_by_openssl_file_loader(path: Path) -> int | None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        context.load_verify_locations(cafile=path)
    except (ssl.SSLError, ValueError):
        return None
    return context.cert_store_stats()["x509"] or None


@pytest.mark.parametrize("case", READING, ids=list(READING))
def test_reading_agrees_with_openssls_own_file_loader(tmp_path, case):
    make, expected = READING[case]
    path = tmp_path / "ca.pem"
    path.write_bytes(make())
    assert count_by_service(path) == expected
    assert count_by_openssl_file_loader(path) == expected
