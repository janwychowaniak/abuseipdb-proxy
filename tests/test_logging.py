"""The check and no_route lines (SPEC §7): their fields in order, and never the key.

The app is built inside each test, after capsys has taken stdout, because the log
handler binds the stdout it finds when create_app configures logging.
"""

import json

import pytest
import requests
from conftest import CHECK
from fastapi.testclient import TestClient

from abuseipdb_proxy.app import create_app

KEY = "test-key-not-real"  # the settings fixture's


def lines(stdout: str, event: str) -> list[dict]:
    parsed = [json.loads(line) for line in stdout.splitlines() if line.startswith("{")]
    return [line for line in parsed if line.get("event") == event]


def the_line(capsys, event: str = "check") -> dict:
    """The one line of `event`, without its timestamp; the key in no line at all."""
    out = capsys.readouterr().out
    assert KEY not in out
    [line] = lines(out, event)
    del line["ts"]
    return line


def drop_latency(line: dict) -> dict:
    assert isinstance(line.pop("upstream_ms"), int)
    return line


def test_a_2xx_line(settings, fake_upstream, capsys):
    client = TestClient(create_app(settings))
    fake_upstream.arm_capture("whitelisted-google-dns")
    client.post(CHECK, json={"artifact": "8.8.8.8", "msg": "k1"})
    line = drop_latency(the_line(capsys))
    assert list(line) == [
        "level", "logger", "message", "event", "our_status", "artifact", "ip", "threshold",
        "max_age_days", "verbose", "msg", "upstream_status", "score", "known", "thresh_gte",
        "ratelimit_remaining",
    ]  # fmt: skip
    assert line == {
        "level": "INFO",
        "logger": "abuseipdb_proxy",
        "message": "check",
        "event": "check",
        "our_status": 200,
        "artifact": "8.8.8.8",
        "ip": "8.8.8.8",
        "threshold": 30,
        "max_age_days": 30,
        "verbose": False,
        "msg": "k1",
        "upstream_status": 200,
        "score": 0,
        "known": True,
        "thresh_gte": False,
        "ratelimit_remaining": 979,
    }


@pytest.mark.parametrize("sent", [{}, {"msg": None}], ids=["absent", "null"])
def test_no_msg_no_msg_key(settings, fake_upstream, capsys, sent):
    client = TestClient(create_app(settings))
    fake_upstream.arm_capture("whitelisted-google-dns")
    client.post(CHECK, json={"artifact": "8.8.8.8", **sent})
    assert "msg" not in the_line(capsys)


def test_an_empty_msg_is_logged(settings, fake_upstream, capsys):
    client = TestClient(create_app(settings))
    fake_upstream.arm_capture("whitelisted-google-dns")
    client.post(CHECK, json={"artifact": "8.8.8.8", "msg": ""})
    assert the_line(capsys)["msg"] == ""


def test_an_upstream_error_line_carries_code_message_and_upstream(settings, fake_upstream, capsys):
    client = TestClient(create_app(settings))
    fake_upstream.arm_capture("error-bad-key")
    resp = client.post(CHECK, json={"artifact": "8.8.8.8", "msg": "k11"})
    error = resp.json()["error"]
    line = drop_latency(the_line(capsys))
    assert line == {
        "level": "INFO",
        "logger": "abuseipdb_proxy",
        "message": error["message"],
        "event": "check",
        "our_status": 502,
        "code": "UPSTREAM_AUTH",
        "artifact": "8.8.8.8",
        "ip": "8.8.8.8",
        "threshold": 30,
        "max_age_days": 30,
        "verbose": False,
        "msg": "k11",
        "upstream_status": 401,
        "upstream": error["upstream"],
    }


def test_a_low_quota_line_is_a_warning(settings, fake_upstream, capsys):
    client = TestClient(create_app(settings))
    fake_upstream.arm_capture("error-quota-429.RECONSTRUCTED")
    client.post(CHECK, json={"artifact": "8.8.8.8"})
    line = the_line(capsys)
    assert line["level"] == "WARNING"
    assert (line["code"], line["ratelimit_remaining"]) == ("UPSTREAM_QUOTA", 0)
    assert line["upstream"]["status"] == 429  # the upstream's own text stays in the log


def test_a_transport_error_line(settings, fake_upstream, capsys):
    client = TestClient(create_app(settings))
    fake_upstream.arm_exc(requests.exceptions.ConnectionError("refused"))
    client.post(CHECK, json={"artifact": "8.8.8.8"})
    line = drop_latency(the_line(capsys))
    assert line["message"] == "upstream unreachable (ConnectionError)"
    assert (line["our_status"], line["code"]) == (504, "UPSTREAM_TIMEOUT")
    assert "upstream_status" not in line  # no response came
    assert "upstream" not in line


def test_an_invalid_artifact_line(settings, fake_upstream, capsys):
    client = TestClient(create_app(settings))
    client.post(CHECK, json={"artifact": "10.0.0.1", "msg": "k5"})
    assert the_line(capsys) == {
        "level": "INFO",
        "logger": "abuseipdb_proxy",
        "message": "private/special-purpose address — no public reputation exists",
        "event": "check",
        "our_status": 422,
        "code": "INVALID_ARTIFACT",
        "artifact": "10.0.0.1",
        "threshold": 30,
        "max_age_days": 30,
        "verbose": False,
        "msg": "k5",
    }


def test_a_refused_body_line_takes_artifact_and_msg_as_sent(settings, fake_upstream, capsys):
    client = TestClient(create_app(settings))
    client.post(CHECK, json={"artifact": 8, "threshold": 101, "msg": "k4"})
    line = the_line(capsys)
    assert line == {
        "level": "INFO",
        "logger": "abuseipdb_proxy",
        "message": line["message"],
        "event": "check",
        "our_status": 422,
        "code": "VALIDATION_ERROR",
        "artifact": 8,
        "msg": "k4",
    }
    assert line["message"].startswith("artifact: ")


@pytest.mark.parametrize(
    ("raw", "ctype"),
    [('{"artifact":', "application/json"), ("[]", "application/json"), ("x", "text/plain")],
    ids=["truncated JSON", "not an object", "not sent as JSON"],
)
def test_an_unparsed_body_line_has_a_null_artifact(settings, fake_upstream, capsys, raw, ctype):
    client = TestClient(create_app(settings))
    client.post(CHECK, content=raw, headers={"Content-Type": ctype})
    line = the_line(capsys)
    assert (line["our_status"], line["code"], line["artifact"]) == (422, "VALIDATION_ERROR", None)
    assert list(line)[-1] == "artifact"  # nothing else: no msg, no effective values


def test_an_unexpected_failure_still_writes_its_line(settings, fake_upstream, capsys):
    client = TestClient(create_app(settings), raise_server_exceptions=False)
    fake_upstream.arm_exc(RuntimeError("boom"))
    client.post(CHECK, json={"artifact": "8.8.8.8"})
    line = the_line(capsys)
    assert (line["our_status"], line["code"]) == (500, "INTERNAL")
    assert line["message"] == "internal error"
    assert line["ip"] == "8.8.8.8"


@pytest.mark.parametrize(
    ("method", "path", "status", "code", "message"),
    [
        ("GET", "/check/8.8.8.8?verbose=true", 404, "NOT_FOUND", "unknown path"),
        ("GET", CHECK, 405, "METHOD_NOT_ALLOWED", "method not allowed for this path"),
    ],
)
def test_a_routing_error_writes_one_no_route_line(
    settings, fake_upstream, capsys, method, path, status, code, message
):
    client = TestClient(create_app(settings))
    client.request(method, path)
    out = capsys.readouterr().out
    assert lines(out, "check") == []
    [line] = lines(out, "no_route")
    del line["ts"]
    assert line == {
        "level": "INFO",
        "logger": "abuseipdb_proxy",
        "message": message,
        "event": "no_route",
        "our_status": status,
        "code": code,
        "method": method,
        "path": path.split("?")[0],  # never the query string
    }


def test_health_and_the_documents_write_no_line(settings, fake_upstream, capsys):
    client = TestClient(create_app(settings))
    for path in ("/v1/health", "/docs", "/openapi.json"):
        client.get(path)
    out = capsys.readouterr().out
    assert lines(out, "check") == []
    assert lines(out, "no_route") == []
