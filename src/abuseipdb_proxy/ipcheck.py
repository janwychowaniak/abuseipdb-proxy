"""Local input validation per SPEC D3 — reject before any upstream call."""

import ipaddress

type IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_CGNAT = ipaddress.ip_network("100.64.0.0/10")


class InvalidIPError(ValueError):
    """Input rejected by D3; str(exc) is the caller-facing reason."""


def validate_ip(raw: str) -> IPAddress:
    """Parse, unwrap and gate an IP string; return the address to query upstream.

    D3.1 unparseable -> reject; D3.2 zone-id -> reject; D3.3 v4-mapped ->
    unwrap; D3.4 must be global and not multicast -> reject with category.
    """
    try:
        ip: IPAddress = ipaddress.ip_address(raw)
    except ValueError:
        raise InvalidIPError("not a valid IPv4 or IPv6 address") from None

    if isinstance(ip, ipaddress.IPv6Address):
        if ip.scope_id:
            raise InvalidIPError("zone-id is not allowed")
        mapped = ip.ipv4_mapped
        if mapped is not None:
            # The mapped form is a separate, blank identity upstream (F9).
            ip = mapped

    if ip.is_multicast:
        # IANA counts global-scope multicast as reachable, so bare is_global
        # would let it through (F11).
        raise InvalidIPError("multicast address — no public reputation exists")
    if not ip.is_global:
        raise InvalidIPError(f"{_category(ip)} address — no public reputation exists")
    return ip


def _category(ip: IPAddress) -> str:
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_unspecified:
        return "unspecified"
    if isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT:
        # Neither is_private nor is_global on CPython 3.13 (F11).
        return "shared-address-space (CGNAT)"
    if ip.is_private:
        return "private/special-purpose"
    return "non-global"
