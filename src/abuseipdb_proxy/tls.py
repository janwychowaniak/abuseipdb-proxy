"""The TLS context the service verifies the upstream with (SPEC D9).

It is urllib3's own default context, plus the certificates of CA_FILE when the file is
set, and the service hands it to the client in every configuration. The default set is
not loaded here: requests hands every pool the bundle it resolves as ca_certs, and
urllib3 loads that into this context at connect time, so the trust is exactly that
bundle, plus the file.
"""

import ssl

from urllib3.util.ssl_ import create_urllib3_context


def upstream_context(pem: str | None) -> ssl.SSLContext:
    """urllib3's default context, plus pem when given.

    Nothing else on the context changes: the flags, the verify mode, hostname checking
    and the minimum version stay as urllib3 sets them.
    """
    context = create_urllib3_context()
    if pem is not None:
        context.load_verify_locations(cadata=pem)
    return context
