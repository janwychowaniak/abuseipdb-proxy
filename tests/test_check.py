"""The envelope (SPEC §3, D11) and D1/D2/D5/D6 semantics against real captures."""

from importlib.metadata import version

import pytest
from conftest import CHECK, captured
from fastapi.testclient import TestClient

from abuseipdb_proxy.app import create_app
from abuseipdb_proxy.settings import Settings

QUERY_KEYS = ["artifact", "type", "threshold", "max_age_days", "verbose", "msg"]


def test_known_bad_ip_full_envelope(client, fake_upstream):
    fake_upstream.arm_capture("bad-tor-default")
    resp = client.post(CHECK, json={"artifact": "185.220.101.34", "msg": "case-4711"})
    assert resp.status_code == 200
    body = resp.json()
    assert list(body) == ["query", "known", "verdict", "report"]  # exactly four keys
    assert list(body["query"]) == QUERY_KEYS
    assert body["query"] == {
        "artifact": "185.220.101.34",
        "type": "ip",
        "threshold": 30,
        "max_age_days": 30,
        "verbose": False,
        "msg": "case-4711",
    }
    assert body["known"] is True
    assert body["verdict"] == {"score": 100, "thresh_gte": True}
    # report is the upstream data object, unmodified
    assert body["report"] == captured("bad-tor-default")["body"]["data"]


def test_whitelisted_is_known_with_score_zero(client, fake_upstream):
    # D2/F5: whitelist forces score 0 but reports exist; known, not over threshold.
    fake_upstream.arm_capture("whitelisted-google-dns")
    body = client.post(CHECK, json={"artifact": "8.8.8.8"}).json()
    assert body["known"] is True
    assert body["verdict"] == {"score": 0, "thresh_gte": False}
    assert body["report"]["isWhitelisted"] is True


def test_never_reported_is_unknown_with_verdict_and_report_present(client, fake_upstream):
    # D2, O9: the upstream always answers with a record, so known: false keeps both.
    fake_upstream.arm_capture("never-reported")
    body = client.post(CHECK, json={"artifact": "194.177.32.5"}).json()
    assert list(body) == ["query", "known", "verdict", "report"]
    assert body["known"] is False
    assert body["verdict"] == {"score": 0, "thresh_gte": False}
    assert body["report"] == captured("never-reported")["body"]["data"]
    assert body["report"]["lastReportedAt"] is None


def test_reported_outside_window_is_unknown(client, fake_upstream):
    # D2/F3: totalReports is window-scoped; a stale 2022 report does not make it known.
    fake_upstream.arm_capture("reported-outside-window")
    body = client.post(CHECK, json={"artifact": "193.0.6.139"}).json()
    assert body["known"] is False
    assert body["report"]["lastReportedAt"] is not None


def test_score_only_ip_is_known(client, fake_upstream):
    # D2 third clause (audit): nonzero window-invariant score with zero window
    # reports must not read as unknown while thresh_gte fires.
    fake_upstream.arm(
        200,
        body={
            "data": {
                "ipAddress": "87.98.154.146",
                "abuseConfidenceScore": 30,
                "totalReports": 0,
                "isWhitelisted": False,
                "lastReportedAt": "2026-08-03T13:57:23+00:00",
            }
        },
    )
    body = client.post(CHECK, json={"artifact": "87.98.154.146", "max_age_days": 1}).json()
    assert body["known"] is True
    assert body["verdict"] == {"score": 30, "thresh_gte": True}


def test_a_record_without_total_reports_counts_zero_reports(client, fake_upstream):
    fake_upstream.arm(200, body={"data": {"abuseConfidenceScore": 0}})
    body = client.post(CHECK, json={"artifact": "87.98.154.146"}).json()
    assert body["known"] is False
    assert body["verdict"] == {"score": 0, "thresh_gte": False}


def test_threshold_boundary_and_override(client, fake_upstream):
    fake_upstream.arm_capture("midscore-default")
    for threshold, gte in ((30, True), (31, False)):
        body = client.post(CHECK, json={"artifact": "87.98.154.146", "threshold": threshold}).json()
        assert body["verdict"]["thresh_gte"] is gte
        assert body["query"]["threshold"] == threshold


def test_threshold_zero_flags_everything(client, fake_upstream):
    # D6 degenerate case, by design: score 0 >= 0.
    fake_upstream.arm_capture("never-reported")
    body = client.post(CHECK, json={"artifact": "194.177.32.5", "threshold": 0}).json()
    assert body["verdict"]["thresh_gte"] is True
    assert body["query"]["threshold"] == 0


def test_query_echoes_defaults_from_settings(fake_upstream):
    custom = Settings(
        _env_file=None,
        abuseipdb_api_key="test-key-not-real",
        score_threshold=77,
        max_age_days=90,
    )
    client = TestClient(create_app(custom))
    fake_upstream.arm_capture("midscore-age90")
    body = client.post(CHECK, json={"artifact": "87.98.154.146"}).json()
    assert body["query"] == {
        "artifact": "87.98.154.146",
        "type": "ip",
        "threshold": 77,
        "max_age_days": 90,
        "verbose": False,
        "msg": None,
    }
    assert body["verdict"]["thresh_gte"] is False  # 30 < 77
    assert fake_upstream.calls[0]["params"]["maxAgeInDays"] == "90"


def test_query_echoes_explicit_values(client, fake_upstream):
    fake_upstream.arm_capture("midscore-age365")
    sent = {"artifact": "87.98.154.146", "threshold": 25, "max_age_days": 365}
    body = client.post(CHECK, json=sent).json()
    assert body["query"] == {**sent, "type": "ip", "verbose": False, "msg": None}
    assert fake_upstream.calls[0]["params"]["maxAgeInDays"] == "365"


@pytest.mark.parametrize(
    ("sent", "echoed"),
    [({"msg": "case-4711"}, "case-4711"), ({"msg": ""}, ""), ({"msg": None}, None), ({}, None)],
    ids=["a value", "empty", "null", "absent"],
)
def test_msg_is_echoed_as_sent_or_null(client, fake_upstream, sent, echoed):
    fake_upstream.arm_capture("midscore-default")
    body = client.post(CHECK, json={"artifact": "87.98.154.146", **sent}).json()
    assert body["query"]["msg"] == echoed
    assert "msg" not in fake_upstream.calls[0]["params"]  # it never influences behaviour


def test_verbose_is_presence_keyed_upstream(client, fake_upstream):
    # D5 (all three auditors): verbose=false must be OMITTED, never sent literally.
    fake_upstream.arm_capture("bad-tor-verbose")
    body = client.post(CHECK, json={"artifact": "185.220.101.34", "verbose": True}).json()
    assert fake_upstream.calls[0]["params"]["verbose"] == ""
    assert body["query"]["verbose"] is True
    assert isinstance(body["report"]["reports"], list)  # per-report details in raw report

    fake_upstream.arm_capture("bad-tor-default")
    client.post(CHECK, json={"artifact": "185.220.101.34", "verbose": False})
    assert "verbose" not in fake_upstream.calls[1]["params"]
    client.post(CHECK, json={"artifact": "185.220.101.34"})
    assert "verbose" not in fake_upstream.calls[2]["params"]


def test_upstream_receives_key_and_timeout(client, fake_upstream, settings):
    fake_upstream.arm_capture("bad-tor-default")
    client.post(CHECK, json={"artifact": "185.220.101.34"})
    call = fake_upstream.calls[0]
    assert call["headers"]["Key"] == "test-key-not-real"
    assert call["timeout"] == (5, 5)  # (connect, read), SPEC §4


def test_health_no_upstream(client, fake_upstream):
    resp = client.get("/v1/health")
    assert resp.status_code == 200
    assert resp.json() == {
        "status": "ok",
        "name": "abuseipdb-proxy",
        "version": version("abuseipdb-proxy"),
        "extra_ca": False,
        "x509_strict": True,
    }
    assert fake_upstream.calls == []
