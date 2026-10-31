"""Extra CA trust from CA_FILE (SPEC D9).

The file is read once, at startup. Its certificates are trusted in addition to
the default trust for TLS with the upstream; a file that yields none refuses the
start.
"""

import os
import re
import ssl
import stat

# The loader takes PEM text as ASCII only (cadata=str), while OpenSSL's own file
# loader reads bytes. A leading UTF-8 BOM is dropped, as OpenSSL drops it, and
# every other non-ASCII byte becomes "?": outside a PEM block that changes
# nothing, inside one it fails the block, as the raw byte would. Text outside
# the blocks never decides; the loader does.
_UTF8_BOM = b"\xef\xbb\xbf"
_ASCII_ONLY = bytes(range(128)) + b"?" * 128
_SOURCE_LOCATION = re.compile(r"\s*\(_ssl\.c:\d+\)$")


class CAFileError(Exception):
    """CA_FILE cannot be used; the message is the one line the refusal prints."""


def load_ca_file(path: str) -> tuple[str, int]:
    """Read CA_FILE once; return its PEM text and the number of certificates it holds."""
    try:
        mode = os.stat(path).st_mode
    except (FileNotFoundError, NotADirectoryError):
        raise CAFileError(f"CA_FILE: no such file: {path}") from None
    except OSError as exc:
        raise CAFileError(f"CA_FILE: cannot be read ({exc.strerror}): {path}") from None
    # checked before opening: open() on a FIFO would block until a writer appears
    if not stat.S_ISREG(mode):
        raise CAFileError(f"CA_FILE: not a regular file: {path}")
    try:
        with open(path, "rb") as file:
            data = file.read()
    except OSError as exc:
        raise CAFileError(f"CA_FILE: cannot be read ({exc.strerror}): {path}") from None

    pem = data.removeprefix(_UTF8_BOM).translate(_ASCII_ONLY).decode("ascii")
    # counted on a fresh, empty context: get_ca_certs() would skip a certificate
    # without the CA flag, and a context holding the default set would not count
    # a root it already has
    probe = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        probe.load_verify_locations(cadata=pem)
    except (ssl.SSLError, ValueError) as exc:
        reason = _SOURCE_LOCATION.sub("", str(exc))
        raise CAFileError(f"CA_FILE: no certificate could be loaded ({reason}): {path}") from None
    count = probe.cert_store_stats()["x509"]
    if count == 0:
        raise CAFileError(f"CA_FILE: no certificate could be loaded (none found): {path}")
    return pem, count
