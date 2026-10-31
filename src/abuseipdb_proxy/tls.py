"""The TLS context the service verifies the upstream with (SPEC D9, D10).

It is urllib3's own default context, plus the certificates of CA_FILE when the file is
set, and the service hands it to the client in every configuration. The default set is
not loaded here: requests hands every pool the bundle it resolves as ca_certs, and
urllib3 loads that into this context at connect time, so the trust is exactly that
bundle, plus the file.

X509_STRICT decides one flag on it, ssl.VERIFY_X509_STRICT: the RFC 5280 conformance
checks Python 3.13 turns on by default, and urllib3 with it. Verification is never off.
"""

import ssl

from urllib3.util.ssl_ import create_urllib3_context

# The verify errors OpenSSL raises only under the flag: its RFC 5280 checks, in
# check_extensions of x509_vfy.c (OpenSSL 3.0 and 3.5), with OpenSSL's own texts. Not 26
# (unsuitable certificate purpose) or 79 (invalid CA certificate): OpenSSL raises those
# without the flag too. Nor 94 (explicit EC parameters), which it checks whatever the
# flag. Clearing the flag would not reliably cure any of them.
STRICT_ONLY: dict[int, str] = {
    78: "cert info signature and signature algorithm mismatch",
    80: "Path length invalid for non-CA cert",
    81: "Path length given without key usage keyCertSign",
    82: "Key usage keyCertSign invalid for non-CA cert",
    83: "Issuer name empty",
    84: "Subject name empty",
    85: "Missing Authority Key Identifier",
    86: "Missing Subject Key Identifier",
    87: "Empty Subject Alternative Name extension",
    88: "Subject empty and Subject Alt Name extension not critical",
    89: "Basic Constraints of CA cert not marked critical",
    90: "Authority Key Identifier marked critical",
    91: "Subject Key Identifier marked critical",
    92: "CA cert does not include key usage extension",
    93: "Using cert extension requires at least X509v3",
}


class X509StrictError(Exception):
    """X509_STRICT is neither true nor false; the message is the one line the refusal prints."""


def parse_x509_strict(value: str | None) -> bool:
    """X509_STRICT as a boolean: true or false in any case, with surrounding whitespace trimmed.

    Unset or empty means true. Anything else is refused, with the value as given in repr,
    so that a newline or an escape character in it cannot split or forge a log line.
    """
    if not value:
        return True
    word = value.strip().lower()
    if word not in ("true", "false"):
        raise X509StrictError(f"X509_STRICT: expected true or false: {value!r}")
    return word == "true"


def upstream_context(pem: str | None, strict: bool) -> ssl.SSLContext:
    """urllib3's default context, plus pem when given, with the flag decided last.

    Nothing else on the context changes: the other flags, the verify mode, hostname
    checking and the minimum version stay as urllib3 sets them.
    """
    context = create_urllib3_context()
    if pem is not None:
        context.load_verify_locations(cadata=pem)
    if strict:
        context.verify_flags |= ssl.VERIFY_X509_STRICT
    else:
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return context


def is_strict(context: ssl.SSLContext) -> bool:
    return bool(context.verify_flags & ssl.VERIFY_X509_STRICT)


def strict_hint(exc: BaseException) -> str:
    """'; TLS: <reason>, see X509_STRICT' for a failure only the flag causes, else ''."""
    reason = _strict_only_reason(exc)
    return "" if reason is None else f"; TLS: {reason}, see X509_STRICT"


def exception_graph(exc: BaseException) -> list[BaseException]:
    """exc and every exception reachable from it through __cause__ and __context__.

    Both links of every exception are followed, each exception is visited once, and the
    cause comes before the context. One link per exception is not enough: in a proxy
    tunnel urllib3 raises MaxRetryError from an SSLError it built but never raised, so the
    verify error sits on MaxRetryError's suppressed __context__ (SPEC D10).
    """
    graph: list[BaseException] = []
    seen: set[int] = set()
    pending: list[BaseException | None] = [exc]
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        graph.append(current)
        pending += [current.__context__, current.__cause__]  # popped cause first
    return graph


def verify_error(exc: BaseException) -> ssl.SSLCertVerificationError | None:
    """The first verify error on the exception graph, if any."""
    for link in exception_graph(exc):
        if isinstance(link, ssl.SSLCertVerificationError):
            return link
    return None


def _strict_only_reason(exc: BaseException) -> str | None:
    error = verify_error(exc)
    if error is not None:
        return STRICT_ONLY.get(getattr(error, "verify_code", None))
    # no verify error on the graph: recognise the reason by its text
    for link in exception_graph(exc):
        text = str(link)
        for reason in STRICT_ONLY.values():
            if reason in text:
                return reason
    return None
