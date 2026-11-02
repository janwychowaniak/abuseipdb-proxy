"""The request (SPEC §3, D11): D3's content checks and the body's shape. Nothing
invalid, non-global or misshapen may reach upstream."""

import pytest
from conftest import CHECK

# Interpreter-drift canary (SPEC D3.4): the normative rejected categories,
# enumerated explicitly so an ipaddress behavior change fails loudly.
NON_GLOBAL = [
    ("192.168.1.1", "rfc1918"),
    ("10.0.0.5", "rfc1918"),
    ("172.16.0.1", "rfc1918"),
    ("127.0.0.1", "loopback"),
    ("169.254.1.1", "link-local"),
    ("100.64.1.1", "cgnat"),
    ("192.0.2.1", "test-net-1"),
    ("203.0.113.7", "test-net-3"),
    ("198.18.0.1", "benchmark"),
    ("224.0.0.1", "multicast"),
    ("0.0.0.0", "unspecified"),
    ("255.255.255.255", "broadcast"),
    ("::1", "loopback-v6"),
    ("fe80::1", "link-local-v6"),
    ("fd00::1", "ula"),
    ("2001:db8::1", "documentation-v6"),
    ("ff02::1", "multicast-v6"),
    ("::", "unspecified-v6"),
]

UNPARSEABLE = [
    "not-an-ip",
    "8.8.8.8.",
    "8.8.8.8:80",
    "010.8.8.8",
    "3232235777",
    "0xC0A80101",
    "[::1]",  # the bracketed form is not an address
    " ",  # a lone space
    " 8.8.8.8",  # never trimmed
    "8.8.8.8 ",
]


def invalid_artifact(resp) -> str:
    """The answer is 422 INVALID_ARTIFACT with nothing else in its body; its message."""
    assert resp.status_code == 422
    body = resp.json()
    assert list(body) == ["error"]
    assert list(body["error"]) == ["code", "message"]
    assert body["error"]["code"] == "INVALID_ARTIFACT"
    return body["error"]["message"]


@pytest.mark.parametrize("ip", [ip for ip, _ in NON_GLOBAL], ids=[t for _, t in NON_GLOBAL])
def test_non_global_rejected_locally(client, fake_upstream, ip):
    message = invalid_artifact(client.post(CHECK, json={"artifact": ip}))
    assert message.endswith("address — no public reputation exists")
    assert fake_upstream.calls == []  # never reached upstream, no quota burned


@pytest.mark.parametrize("raw", UNPARSEABLE)
def test_unparseable_rejected(client, fake_upstream, raw):
    message = invalid_artifact(client.post(CHECK, json={"artifact": raw}))
    assert message == "not a valid IPv4 or IPv6 address"
    assert fake_upstream.calls == []


def test_zone_id_rejected_even_on_global_address(client, fake_upstream):
    # A zone-id on a *global* v6 passes is_global and would burn quota upstream.
    resp = client.post(CHECK, json={"artifact": "2606:4700:4700::1111%eth0"})
    assert invalid_artifact(resp) == "zone-id is not allowed"
    assert fake_upstream.calls == []


@pytest.mark.parametrize("raw", ["8.8.8.0/24", "8.8.8.8/32", "2001:4860::/32", "/"])
def test_a_network_is_not_a_single_address(client, fake_upstream, raw):
    # SPEC §3: a CIDR typo says what is wrong.
    assert invalid_artifact(client.post(CHECK, json={"artifact": raw})) == "not a single IP address"
    assert fake_upstream.calls == []


def test_v4_mapped_unwrapped_before_query(client, fake_upstream):
    # D3.3/F9: ::ffff:8.8.8.8 is a blank identity upstream; query 8.8.8.8 instead.
    fake_upstream.arm_capture("whitelisted-google-dns")
    resp = client.post(CHECK, json={"artifact": "::ffff:8.8.8.8"})
    assert resp.status_code == 200
    assert fake_upstream.calls[0]["params"]["ipAddress"] == "8.8.8.8"
    assert resp.json()["query"]["artifact"] == "::ffff:8.8.8.8"  # caller's spelling echoed
    assert resp.json()["report"]["ipAddress"] == "8.8.8.8"


def test_v4_mapped_private_rejected(client, fake_upstream):
    message = invalid_artifact(client.post(CHECK, json={"artifact": "::ffff:192.168.1.1"}))
    assert message == "private/special-purpose address — no public reputation exists"
    assert fake_upstream.calls == []


def test_canonical_form_sent_upstream(client, fake_upstream):
    # D3.5: uncompressed spelling goes upstream compressed and lowercase.
    fake_upstream.arm_capture("ipv6-google-dns")
    resp = client.post(CHECK, json={"artifact": "2001:4860:4860:0:0:0:0:8888"})
    assert resp.status_code == 200
    assert fake_upstream.calls[0]["params"]["ipAddress"] == "2001:4860:4860::8888"
    assert resp.json()["query"]["artifact"] == "2001:4860:4860:0:0:0:0:8888"


# --- the body's shape: 422 VALIDATION_ERROR, before any check of its content -----------


def with_artifact(member: str) -> str:
    """A JSON object of a valid artifact and one more member, as raw text."""
    return '{"artifact": "8.8.8.8", ' + member + "}"


SHAPE = [
    ("an empty object", "{}", "artifact: "),
    ("an empty artifact", '{"artifact": ""}', "artifact: "),
    ("a number as artifact", '{"artifact": 8}', "artifact: "),
    ("null as artifact", '{"artifact": null}', "artifact: "),
    ("threshold above 100", with_artifact('"threshold": 101'), "threshold: "),
    ("threshold below 0", with_artifact('"threshold": -1'), "threshold: "),
    ("max_age_days 0", with_artifact('"max_age_days": 0'), "max_age_days: "),
    ("max_age_days 366", with_artifact('"max_age_days": 366'), "max_age_days: "),
    ("null as threshold", with_artifact('"threshold": null'), "threshold: "),
    ("null as max_age_days", with_artifact('"max_age_days": null'), "max_age_days: "),
    ("null as verbose", with_artifact('"verbose": null'), "verbose: "),
    ("true as threshold", with_artifact('"threshold": true'), "threshold: "),
    ("5.0 as threshold", with_artifact('"threshold": 5.0'), "threshold: "),
    ("a string as threshold", with_artifact('"threshold": "5"'), "threshold: "),
    ("a string as max_age_days", with_artifact('"max_age_days": "30"'), "max_age_days: "),
    ("a string as verbose", with_artifact('"verbose": "true"'), "verbose: "),
    ("1 as verbose", with_artifact('"verbose": 1'), "verbose: "),
    ("a number as msg", with_artifact('"msg": 5'), "msg: "),
    ("an unknown field", with_artifact('"foo": 1'), "foo: "),
    ("a list", "[]", "body: "),
    ("a string", '"8.8.8.8"', "body: "),
]


@pytest.mark.parametrize(
    ("raw", "field"), [(r, f) for _, r, f in SHAPE], ids=[i for i, _, _ in SHAPE]
)
def test_a_misshapen_body_is_validation_error(client, fake_upstream, raw, field):
    resp = client.post(CHECK, content=raw, headers={"Content-Type": "application/json"})
    assert resp.status_code == 422
    assert list(resp.json()) == ["error"]
    error = resp.json()["error"]
    assert list(error) == ["code", "message"]
    assert error["code"] == "VALIDATION_ERROR"
    assert error["message"].startswith(field)
    assert fake_upstream.calls == []


@pytest.mark.parametrize(
    ("raw", "ctype", "message"),
    [
        ('{"artifact":', "application/json", "body: JSON decode error at position 12"),
        ("not json", "application/json", "body: JSON decode error at position 0"),
        ("", "application/json", "body: Field required"),
        ('{"artifact": "8.8.8.8"}', "text/plain", None),
    ],
    ids=["truncated JSON", "not JSON", "no body", "not sent as JSON"],
)
def test_an_unreadable_body_is_validation_error(client, fake_upstream, raw, ctype, message):
    resp = client.post(CHECK, content=raw, headers={"Content-Type": ctype})
    assert resp.status_code == 422
    error = resp.json()["error"]
    assert error["code"] == "VALIDATION_ERROR"
    assert error["message"].startswith("body: ")
    if message is not None:
        assert error["message"] == message
    assert fake_upstream.calls == []


def test_every_shape_failure_is_named(client, fake_upstream):
    raw = '{"threshold": -1, "foo": 1}'
    resp = client.post(CHECK, content=raw, headers={"Content-Type": "application/json"})
    message = resp.json()["error"]["message"]
    assert [part.split(":")[0] for part in message.split("; ")] == ["artifact", "threshold", "foo"]


def test_query_string_parameters_are_ignored(client, fake_upstream):
    fake_upstream.arm_capture("midscore-default")
    resp = client.post(
        f"{CHECK}?threshold=99&max_age_days=7&verbose=true", json={"artifact": "87.98.154.146"}
    )
    assert resp.status_code == 200
    query = resp.json()["query"]
    assert (query["threshold"], query["max_age_days"], query["verbose"]) == (30, 30, False)
    assert fake_upstream.calls[0]["params"] == {"ipAddress": "87.98.154.146", "maxAgeInDays": "30"}
