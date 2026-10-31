"""X509_STRICT (SPEC D10): the one flag it decides on the upstream TLS context, the startup
refusal, what health and the log say, and the hint a failed verification gets.

The non-conforming authority is a trustme CA re-signed with its own key and contents, its
Basic Constraints and Key Usage not marked critical, though RFC 5280 requires Basic
Constraints to be critical on a CA certificate. Certificates are generated per run and
never committed; requests go through the client a deployment builds, against TLS servers
and proxies on loopback.
"""

import json
import socket
import ssl
from urllib.parse import urlsplit

import pytest
import requests
import requests.adapters
import trustme
from conftest import (
    API_KEY,
    NO_UPSTREAM,
    assert_reached,
    assert_refused,
    connect_proxy,
    leaf_from,
    pem_file,
    run_entrypoint,
    service,
    settings_for,
    tls_upstream,
)
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient
from urllib3.util.ssl_ import create_urllib3_context

from abuseipdb_proxy import tls, upstream
from abuseipdb_proxy.app import create_app

pytestmark = pytest.mark.usefixtures("isolated_client")

REFUSED = "upstream-timeout: upstream unreachable (SSLError)"
HINT = "; TLS: Basic Constraints of CA cert not marked critical, see X509_STRICT"
HINTED = REFUSED + HINT
PROXY_REFUSED = "upstream-timeout: upstream unreachable (ProxyError)"


def non_conforming(ca: trustme.CA) -> trustme.CA:
    """`ca` re-signed with its own key and contents, Basic Constraints and Key Usage not
    critical."""
    cert = x509.load_pem_x509_certificate(ca.cert_pem.bytes())
    key = serialization.load_pem_private_key(ca.private_key_pem.bytes(), password=None)
    builder = (
        x509.CertificateBuilder()
        .subject_name(cert.subject)
        .issuer_name(cert.issuer)
        .public_key(cert.public_key())
        .serial_number(cert.serial_number)
        .not_valid_before(cert.not_valid_before_utc)
        .not_valid_after(cert.not_valid_after_utc)
    )
    for extension in cert.extensions:
        relaxed = isinstance(extension.value, x509.BasicConstraints | x509.KeyUsage)
        builder = builder.add_extension(extension.value, extension.critical and not relaxed)
    resigned = builder.sign(key, cert.signature_hash_algorithm)  # type: ignore[arg-type]
    return trustme.CA.from_pem(
        resigned.public_bytes(serialization.Encoding.PEM), ca.private_key_pem.bytes()
    )


def log_lines(stdout: str, event: str) -> list[dict]:
    lines = [json.loads(line) for line in stdout.splitlines() if line.startswith("{")]
    return [line for line in lines if line.get("event") == event]


# --- the flag on the context ------------------------------------------------------------


def test_false_clears_that_one_flag_and_nothing_else():
    default, relaxed = create_urllib3_context(), tls.upstream_context(None, False)
    assert default.verify_flags & ~relaxed.verify_flags == ssl.VERIFY_X509_STRICT
    assert relaxed.verify_flags | ssl.VERIFY_X509_STRICT == default.verify_flags
    for attribute in (
        "verify_mode",
        "check_hostname",
        "options",
        "minimum_version",
        "maximum_version",
        "security_level",
    ):
        assert getattr(relaxed, attribute) == getattr(default, attribute), attribute


def test_true_sets_the_flag_whatever_the_librarys_default(monkeypatch):
    def without_the_flag() -> ssl.SSLContext:
        context = create_urllib3_context()
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT
        return context

    monkeypatch.setattr(tls, "create_urllib3_context", without_the_flag)
    assert tls.is_strict(tls.upstream_context(None, True))
    assert not tls.is_strict(tls.upstream_context(None, False))


# --- trust under the flag ---------------------------------------------------------------


@pytest.mark.loopback
def test_the_default_refuses_a_non_conforming_authority_with_a_hint(tmp_path, capsys):
    ca = non_conforming(trustme.CA())
    with tls_upstream(leaf_from(ca)) as url:
        assert assert_refused(service(url, pem_file(tmp_path / "ca.pem", ca.cert_pem))) == HINTED
    [line] = log_lines(capsys.readouterr().out, "check")
    assert line["our_status"] == 504
    assert line["detail"] == HINTED  # the check line carries the same text


@pytest.mark.loopback
def test_false_admits_the_non_conforming_authority(tmp_path):
    ca = non_conforming(trustme.CA())
    with tls_upstream(leaf_from(ca)) as url:
        client = service(url, pem_file(tmp_path / "ca.pem", ca.cert_pem), "false")
        assert_reached(client)
        # loading the bundle into the context at connect time leaves the flag alone
        assert client.get("/health").json()["x509_strict"] is False


@pytest.mark.loopback
@pytest.mark.parametrize("value", ["true", "false"])
def test_an_authority_in_neither_set_is_refused_without_a_hint(tmp_path, value):
    ca_file = pem_file(tmp_path / "ca.pem", non_conforming(trustme.CA()).cert_pem)
    with tls_upstream(leaf_from(trustme.CA())) as url:
        assert assert_refused(service(url, ca_file, value)) == REFUSED  # verification stays on


@pytest.mark.loopback
def test_the_flag_acts_on_the_bundle_requests_ca_bundle_selects(tmp_path, monkeypatch):
    ca = non_conforming(trustme.CA())
    # no CA_FILE: the client's own default set, selected by its own variable
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", pem_file(tmp_path / "bundle.pem", ca.cert_pem))
    with tls_upstream(leaf_from(ca)) as url:
        assert_reached(service(url, x509_strict="false"))
        assert assert_refused(service(url)) == HINTED


@pytest.mark.loopback
def test_the_flag_acts_on_the_default_bundle_on_the_deployment_path(tmp_path, monkeypatch):
    ca = non_conforming(trustme.CA())
    bundle = pem_file(tmp_path / "default.pem", ca.cert_pem)
    monkeypatch.setattr(requests.adapters, "DEFAULT_CA_BUNDLE_PATH", bundle)
    with tls_upstream(leaf_from(ca)) as url:
        assert_reached(service(url, x509_strict="false"))
        assert assert_refused(service(url)) == HINTED


@pytest.mark.loopback
@pytest.mark.parametrize("value", ["true", "false"])
def test_both_values_admit_a_conforming_authority(tmp_path, value):
    ca = trustme.CA()
    with tls_upstream(leaf_from(ca)) as url:
        assert_reached(service(url, pem_file(tmp_path / "ca.pem", ca.cert_pem), value))


@pytest.mark.loopback
def test_through_a_connect_tunnel_the_hint_shows_and_false_reaches(tmp_path, monkeypatch):
    ca = non_conforming(trustme.CA())
    ca_file = pem_file(tmp_path / "ca.pem", ca.cert_pem)
    with tls_upstream(leaf_from(ca)) as url, connect_proxy() as (proxy_url, seen):
        monkeypatch.setenv("HTTPS_PROXY", proxy_url)
        assert assert_refused(service(url, ca_file)) == HINTED
        assert_reached(service(url, ca_file, "false"))
    assert seen == [f"CONNECT 127.0.0.1:{urlsplit(url).port}"] * 2


@pytest.mark.loopback
def test_at_an_https_proxy_endpoint_false_cannot_reach_that_hop(tmp_path, monkeypatch):
    # The proxy's own certificate is under the non-conforming authority, which the
    # client's own bundle trusts. That hop keeps urllib3's default context (D9 3): the
    # hint shows while the flag is set, and with it cleared the failure stays.
    proxy_ca, ca = non_conforming(trustme.CA()), trustme.CA()
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", pem_file(tmp_path / "bundle.pem", proxy_ca.cert_pem))
    ca_file = pem_file(tmp_path / "ca.pem", ca.cert_pem)
    with (
        tls_upstream(leaf_from(ca)) as url,
        connect_proxy(tls=leaf_from(proxy_ca)) as (proxy_url, seen),
    ):
        monkeypatch.setenv("HTTPS_PROXY", proxy_url)
        assert assert_refused(service(url, ca_file)) == PROXY_REFUSED + HINT
        assert assert_refused(service(url, ca_file, "false")) == PROXY_REFUSED
    assert seen == []  # the TLS with the proxy failed before any CONNECT


@pytest.mark.loopback
def test_a_refused_connection_keeps_its_message():
    with socket.socket() as probe:  # a loopback port nothing listens on
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    detail = assert_refused(service(f"https://127.0.0.1:{port}/api/v2"))
    assert detail == "upstream-timeout: upstream unreachable (ConnectionError)"


# --- the setting: refusals, health and the startup line ---------------------------------


def refusal(**fields: str) -> str:
    """The one line create_app ends the process with, for these settings."""
    with pytest.raises(SystemExit) as exited:
        create_app(settings_for(NO_UPSTREAM, **fields))
    line = exited.value.code
    assert isinstance(line, str)
    assert API_KEY not in line
    return line


NOT_BOOLEAN = ["maybe", "0", "1", "yes", "no", "on", "off", " ", "true\nfalse"]


@pytest.mark.parametrize("value", NOT_BOOLEAN, ids=[repr(value) for value in NOT_BOOLEAN])
def test_only_true_and_false_are_values(value):
    line = refusal(x509_strict=value)
    assert line == f"X509_STRICT: expected true or false: {value!r}"
    assert "\n" not in line  # repr keeps the line whole


def test_x509_strict_is_checked_before_ca_file_is_read(tmp_path):
    line = refusal(x509_strict="maybe", ca_file=str(tmp_path / "missing.pem"))
    assert line == "X509_STRICT: expected true or false: 'maybe'"


@pytest.mark.parametrize("value", ["maybe", "0"])
def test_the_refusal_is_the_only_output_of_the_real_entrypoint(tmp_path, value):
    result = run_entrypoint(tmp_path, ABUSEIPDB_API_KEY=API_KEY, X509_STRICT=value)
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == f"X509_STRICT: expected true or false: {value!r}\n"


def test_a_missing_key_is_reported_before_x509_strict(tmp_path):
    result = run_entrypoint(tmp_path, X509_STRICT="maybe")
    assert result.returncode == 1
    assert result.stdout == ""
    # the key's own error, unchanged: pydantic's ValidationError naming the field
    assert "ValidationError" in result.stderr
    assert "abuseipdb_api_key" in result.stderr
    assert "X509_STRICT:" not in result.stderr


def test_false_logs_nothing_before_a_ca_file_refusal(tmp_path):
    # the warning comes after CA_FILE is read, so the file's refusal stays the only output
    missing = tmp_path / "missing.pem"
    result = run_entrypoint(
        tmp_path, ABUSEIPDB_API_KEY=API_KEY, X509_STRICT="false", CA_FILE=str(missing)
    )
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == f"CA_FILE: no such file: {missing}\n"


SPELLINGS = [
    (None, True),
    ("", True),
    ("true", True),
    ("TRUE", True),
    ("false", False),
    ("FALSE", False),
    (" False ", False),
]


@pytest.mark.parametrize(("value", "strict"), SPELLINGS, ids=[repr(v) for v, _ in SPELLINGS])
def test_health_says_what_the_context_carries_and_false_logs_one_warning(value, strict, capsys):
    body = service(NO_UPSTREAM, x509_strict=value).get("/health").json()
    assert list(body) == ["status", "name", "version", "extra_ca", "x509_strict"]
    assert body["x509_strict"] is strict
    warnings = log_lines(capsys.readouterr().out, "x509_strict_disabled")
    assert len(warnings) == (0 if strict else 1)


def test_the_warning_is_a_bare_line_after_the_ca_file_line(tmp_path, capsys):
    service(NO_UPSTREAM, pem_file(tmp_path / "ca.pem", trustme.CA().cert_pem), "false")
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [line["event"] for line in lines] == ["ca_file_loaded", "x509_strict_disabled"]
    del lines[1]["ts"]
    assert lines[1] == {
        "level": "WARNING",
        "logger": "abuseipdb_proxy",
        "message": "x509_strict_disabled",
        "event": "x509_strict_disabled",
    }


def test_health_reads_the_context_not_the_setting(monkeypatch):
    # with a context builder that ignores the setting, health follows the context
    built = tls.upstream_context
    monkeypatch.setattr(tls, "upstream_context", lambda pem, strict: built(pem, True))
    body = service(NO_UPSTREAM, x509_strict="false").get("/health").json()
    assert body["x509_strict"] is True


# --- recognising the failures only the flag causes --------------------------------------


def failed_verification(code: int) -> requests.exceptions.SSLError:
    """A requests SSLError with a verify error of `code` on its context."""
    error = ssl.SSLCertVerificationError(
        1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"
    )
    error.verify_code = code
    outer = requests.exceptions.SSLError("Max retries exceeded (Caused by SSLError(...))")
    outer.__context__ = error
    return outer


@pytest.mark.parametrize("code", sorted(tls.STRICT_ONLY))
def test_each_failure_only_the_flag_causes_gets_its_hint(code):
    hint = f"; TLS: {tls.STRICT_ONLY[code]}, see X509_STRICT"
    assert tls.strict_hint(failed_verification(code)) == hint


@pytest.mark.parametrize("code", [20, 26, 62, 79, 94])
def test_other_failures_get_none(code):
    # an unknown issuer, an unsuitable purpose, a hostname mismatch; 26 and 79 occur
    # without the flag too, and 94 is checked whatever the flag
    assert tls.strict_hint(failed_verification(code)) == ""


def test_without_a_verify_error_the_text_is_recognised():
    message = (
        "HTTPSConnectionPool(host='127.0.0.1', port=443): Max retries exceeded with url: "
        "/api/v2/check (Caused by SSLError(SSLCertVerificationError(1, '[SSL: "
        "CERTIFICATE_VERIFY_FAILED] certificate verify failed: Missing Authority Key "
        "Identifier (_ssl.c:1032)')))"
    )
    hint = "; TLS: Missing Authority Key Identifier, see X509_STRICT"
    assert tls.strict_hint(requests.exceptions.SSLError(message)) == hint


def test_an_error_that_is_no_failed_verification_gets_none():
    refused = requests.exceptions.ConnectionError("[Errno 111] Connection refused")
    assert tls.strict_hint(refused) == ""


@pytest.mark.parametrize(("value", "detail"), [("true", HINTED), ("false", REFUSED)])
def test_only_a_context_with_the_flag_gives_the_hint(fake_upstream, value, detail):
    fake_upstream.arm_exc(failed_verification(89))
    client = TestClient(create_app(settings_for(NO_UPSTREAM, x509_strict=value)))
    assert assert_refused(client) == detail


def caught(base_url: str, ca_file: str) -> requests.exceptions.RequestException:
    """What the upstream call raises, through the client create_app builds."""
    settings = settings_for(base_url, ca_file)
    create_app(settings)
    with pytest.raises(requests.exceptions.RequestException) as raised:
        upstream.check(settings, "87.98.154.146", 30, False)
    return raised.value


SHAPES = ["direct", "inside a CONNECT tunnel", "at an https:// proxy endpoint"]


@pytest.mark.loopback
@pytest.mark.parametrize("shape", SHAPES)
def test_the_walk_alone_finds_the_verify_error(shape, tmp_path, monkeypatch):
    # The family's text is in str() of every shape, so the text fallback would hide a
    # walk that misses; this checks the walk alone, on failures captured on loopback.
    ca = non_conforming(trustme.CA())
    ca_file = pem_file(tmp_path / "ca.pem", ca.cert_pem)
    if shape == "at an https:// proxy endpoint":
        upstream_ca = trustme.CA()
        monkeypatch.setenv("REQUESTS_CA_BUNDLE", ca_file)  # the proxy hop trusts it
        with (
            tls_upstream(leaf_from(upstream_ca)) as url,
            connect_proxy(tls=leaf_from(ca)) as (proxy_url, _),
        ):
            monkeypatch.setenv("HTTPS_PROXY", proxy_url)
            exc = caught(url, pem_file(tmp_path / "upstream-ca.pem", upstream_ca.cert_pem))
    else:
        with tls_upstream(leaf_from(ca)) as url, connect_proxy() as (proxy_url, _):
            if shape == "inside a CONNECT tunnel":
                monkeypatch.setenv("HTTPS_PROXY", proxy_url)
            exc = caught(url, ca_file)
    error = tls.verify_error(exc)
    assert error is not None
    assert error.verify_code == 89
