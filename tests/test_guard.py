"""The network guard itself (SPEC §6): numeric loopback only, and only when marked."""

import socket

import pytest
from conftest import admitted_by_guard

ADMITTED = {
    "IPv4 loopback": ("127.0.0.1", 9),
    "anywhere in 127.0.0.0/8": ("127.255.0.1", 9),
    "IPv6 loopback": ("::1", 9),
    "IPv6 loopback, 4-tuple": ("::1", 9, 0, 0),
}

REFUSED = {
    "a non-loopback IPv4 address": ("192.0.2.1", 9),
    "a non-loopback IPv6 address, 4-tuple": ("2001:db8::1", 9, 0, 0),
    "a name, even for loopback": ("localhost", 9),
    "an AF_UNIX path": "/run/abuseipdb-proxy.sock",
    "an abstract AF_UNIX name": b"\0abuseipdb-proxy",
    "a tuple without a port": ("127.0.0.1",),
}


# ::1 is checked here rather than with a live socket, so the suite does not
# depend on a host that has IPv6 loopback configured.
@pytest.mark.parametrize("address", ADMITTED.values(), ids=list(ADMITTED))
def test_numeric_loopback_is_admitted(address):
    assert admitted_by_guard(address) is True


@pytest.mark.parametrize("address", REFUSED.values(), ids=list(REFUSED))
def test_anything_else_is_refused(address):
    assert admitted_by_guard(address) is False


@pytest.mark.loopback
def test_a_loopback_test_reaches_a_loopback_listener():
    with socket.create_server(("127.0.0.1", 0)) as server, socket.socket() as client:
        client.connect(server.getsockname())


@pytest.mark.loopback
def test_a_loopback_test_still_cannot_reach_another_address():
    # refused before any packet leaves: the real connect() is never called
    with socket.socket() as sock, pytest.raises(AssertionError, match="real network connection"):
        sock.connect(("192.0.2.1", 9))


def test_an_unmarked_test_cannot_reach_loopback():
    with (
        socket.create_server(("127.0.0.1", 0)) as server,
        socket.socket() as client,
        pytest.raises(AssertionError, match="real network connection"),
    ):
        client.connect(server.getsockname())
