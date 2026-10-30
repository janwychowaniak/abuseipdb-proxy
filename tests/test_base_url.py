"""ABUSEIPDB_BASE_URL (SPEC §4): the prefix up to /api/v2, for tests and mocks."""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from abuseipdb_proxy.app import create_app
from abuseipdb_proxy.settings import Settings


def settings_with(base_url: str) -> Settings:
    return Settings(
        _env_file=None, abuseipdb_api_key="test-key-not-real", abuseipdb_base_url=base_url
    )


def test_the_default_is_the_abuseipdb_api(client, fake_upstream):
    fake_upstream.arm_capture("midscore-default")
    client.get("/check/87.98.154.146")
    assert fake_upstream.calls[0]["url"] == "https://api.abuseipdb.com/api/v2/check"


@pytest.mark.parametrize(
    ("base_url", "called"),
    [
        ("https://mock.invalid/api/v2", "https://mock.invalid/api/v2/check"),
        ("https://mock.invalid/api/v2/", "https://mock.invalid/api/v2/check"),
        ("http://127.0.0.1:8080/mock", "http://127.0.0.1:8080/mock/check"),
    ],
    ids=["https", "a trailing slash", "plain http"],
)
def test_the_override_replaces_the_prefix_and_check_is_appended(fake_upstream, base_url, called):
    fake_upstream.arm_capture("midscore-default")
    TestClient(create_app(settings_with(base_url))).get("/check/87.98.154.146")
    assert fake_upstream.calls[0]["url"] == called


@pytest.mark.parametrize("base_url", ["api.abuseipdb.com/api/v2", "ftp://mock.invalid", ""])
def test_a_value_that_is_not_http_refuses_the_start(base_url):
    with pytest.raises(ValidationError, match="ABUSEIPDB_BASE_URL must start with"):
        settings_with(base_url)
