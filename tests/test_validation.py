"""D3 local validation: nothing invalid or non-global may reach upstream."""

import pytest

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
    "%5B::1%5D",  # decodes to "[::1]" — bracketed form is not an address
    "%20",  # decodes to a lone space
]


@pytest.mark.parametrize("ip", [ip for ip, _ in NON_GLOBAL], ids=[t for _, t in NON_GLOBAL])
def test_non_global_rejected_locally(client, fake_upstream, ip):
    resp = client.get(f"/check/{ip}")
    assert resp.status_code == 400
    assert isinstance(resp.json()["detail"], str)
    assert fake_upstream.calls == []  # never reached upstream, no quota burned


@pytest.mark.parametrize("raw", UNPARSEABLE)
def test_unparseable_rejected(client, fake_upstream, raw):
    resp = client.get(f"/check/{raw}")
    assert resp.status_code == 400
    assert "not a valid" in resp.json()["detail"]
    assert fake_upstream.calls == []


def test_zone_id_rejected_even_on_global_address(client, fake_upstream):
    # A zone-id on a *global* v6 passes is_global and would burn quota upstream.
    resp = client.get("/check/2606:4700:4700::1111%25eth0")
    assert resp.status_code == 400
    assert "zone-id" in resp.json()["detail"]
    assert fake_upstream.calls == []


def test_v4_mapped_unwrapped_before_query(client, fake_upstream):
    # D3.3/F9: ::ffff:8.8.8.8 is a blank identity upstream; query 8.8.8.8 instead.
    fake_upstream.arm_capture("whitelisted-google-dns")
    resp = client.get("/check/::ffff:8.8.8.8")
    assert resp.status_code == 200
    assert fake_upstream.calls[0]["params"]["ipAddress"] == "8.8.8.8"
    assert resp.json()["query"] == "::ffff:8.8.8.8"  # caller's spelling echoed


def test_v4_mapped_private_rejected(client, fake_upstream):
    resp = client.get("/check/::ffff:192.168.1.1")
    assert resp.status_code == 400
    assert fake_upstream.calls == []


def test_canonical_form_sent_upstream(client, fake_upstream):
    # D3.5: uncompressed spelling goes upstream compressed and lowercase.
    fake_upstream.arm_capture("ipv6-google-dns")
    resp = client.get("/check/2001:4860:4860:0:0:0:0:8888")
    assert resp.status_code == 200
    assert fake_upstream.calls[0]["params"]["ipAddress"] == "2001:4860:4860::8888"
    assert resp.json()["query"] == "2001:4860:4860:0:0:0:0:8888"


def test_cidr_hits_catchall_not_404(client, fake_upstream):
    # SPEC §3: a CIDR typo must not surface as 404 ("IP unknown" to VT habits).
    resp = client.get("/check/8.8.8.0/24")
    assert resp.status_code == 400
    assert resp.json()["detail"] == "not a single IP address"
    assert fake_upstream.calls == []


def test_trailing_slash_hits_catchall(client, fake_upstream):
    assert client.get("/check/").status_code == 400


def test_query_param_validation_is_400_with_string_detail(client, fake_upstream):
    # SPEC §3: FastAPI's native 422-with-list shape is not part of the contract.
    for url in (
        "/check/8.8.8.8?threshold=101",
        "/check/8.8.8.8?threshold=abc",
        "/check/8.8.8.8?max_age_days=0",
        "/check/8.8.8.8?max_age_days=366",
    ):
        resp = client.get(url)
        assert resp.status_code == 400, url
        assert isinstance(resp.json()["detail"], str), url
    assert fake_upstream.calls == []
