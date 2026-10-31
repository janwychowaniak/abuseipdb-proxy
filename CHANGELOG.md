# Changelog

The release notes are the annotated tag messages. This file carries the same
notes where they can be read without git, together with the image digest each
version was published under, its image Id (configuration digest) and the
Python it runs, and corrections to them as errata.

**A tag is never pushed again, not even to fix its message.** Pushing it runs
the release again and can publish the same version under a different digest,
which breaks the one property a pinned deployment stands on. A wrong line in
a tag message is corrected here instead, as an erratum that says what the tag
claims and what is true.

The image Id is what a host compares after `docker load` of a release file.
On Docker's default `overlay2` image store, it is the digest of the image's
configuration, which the archive carries byte for byte (see the README).

## 0.3.0 — 2026-10-31

`ghcr.io/janwychowaniak/abuseipdb-proxy@sha256:fd4b2fb0731b793f9fc2e6c60b268271100beb0504be7749c6ec2eb4d330cca8`

Image Id (configuration digest)
`sha256:e4f99d7fed2f54bc3798ca7a2f3c2db56a34ab9d87268a754e2a007410e238e2`,
after a pull and after `docker load` of the release file alike. Python
3.13.18.

An opt-out of Python's strict X.509 checks, for an authority that cannot
conform.

- X509_STRICT (new, optional, default true): with false, the service clears
  ssl.VERIFY_X509_STRICT, and only that flag, on the TLS context it verifies
  AbuseIPDB with, directly or through a proxy tunnel; the TLS of an https://
  proxy endpoint itself keeps its default checks. Verification stays on: the
  chain is still verified against the trusted authorities, CA_FILE included,
  and the hostname is still checked. The values are true and false, in any
  letter case, with surrounding whitespace ignored; unset or empty means true,
  and any other value refuses the start with one line naming X509_STRICT.
- GET /health gains "x509_strict", the state the TLS context carries; a start
  with false logs one x509_strict_disabled warning.
- A failed verification that only the strict checks cause still answers 504
  upstream-timeout:; while the checks are on, its detail now names OpenSSL's
  reason and points at X509_STRICT.

Unset, the checks are those 0.2.0 ran; only the message of a failure they
cause grows. Unchanged: the /check endpoint and its response, the error
contract (statuses and detail prefixes), CA_FILE, the proxy variables, and the
non-root, classic-builder-compatible image.

## 0.2.0 — 2026-10-30

`ghcr.io/janwychowaniak/abuseipdb-proxy@sha256:0f25e661103f0f7ac1e71d255ee0984a53138e87a2fceb59c353aaeefc8278f1`

Image Id (configuration digest)
`sha256:bf2da8382527f36a218c32a48709cab5d9d16667a4407a6be237e09e833ac28a`,
after a pull and after `docker load` of the release file alike. Python
3.13.18.

Extra CA trust without a derived image, and the image as a release file.

- CA_FILE (new, optional): a PEM file of certificate authorities trusted in
  addition to the default ones for TLS with AbuseIPDB, directly or through a
  proxy tunnel; the TLS of an https:// proxy endpoint itself keeps the
  default trust. Read once at startup; a missing, unreadable or
  certificate-less file refuses the start with one line naming CA_FILE.
  Verification is never switched off.
- GET /health gains "name", "version" and "extra_ca" (true when CA_FILE is
  loaded).
- compose.ca.yml mounts the file and sets the variable; the derived-image
  recipe is gone from the documentation.
- ABUSEIPDB_BASE_URL (new, optional) overrides the upstream base URL, for
  tests and mocks.
- Every release now carries the published image as
  abuseipdb-proxy-<version>.tar.gz, saved by its full tag, with its .sha256;
  CHANGELOG.md records each version's digest and image Id (configuration
  digest).

Unchanged: the /check endpoint and its response, the error contract (a
failed TLS verification is still 504 upstream-timeout:), and the proxy
variables.

## 0.1.1 — 2026-08-13

`ghcr.io/janwychowaniak/abuseipdb-proxy@sha256:b45dafd58973c16e55fb530a4b53461eba7f44200d521cc950a3224dd264a544`,
the digest the `0.1.1` tag resolved to in the registry on 2026-10-30, when
this entry was written.

Image Id (configuration digest)
`sha256:b3e1c5edc0ba9ed7957d855ddfe95284ec93793e52f8ef057c2ae5d5460964c6`,
the configuration that manifest names, which a pull shows as the Id on
`overlay2`. Created 2026-08-13T20:11:39Z; Python 3.13.15. The creation time
and the Python were read from the image configuration in the registry,
without a pull. No GitHub Release exists for this tag.

abuseipdb-proxy 0.1.1 — non-root runtime user, HEALTHCHECK, OCI labels

## 0.1.0 — 2026-08-10

`ghcr.io/janwychowaniak/abuseipdb-proxy@sha256:9ff317ac3602074daef684ecac2d01387000f8ca7f610f15dc020a9b90f0a93a`,
the digest the `0.1.0` tag resolved to in the registry on 2026-10-30, when
this entry was written.

Image Id (configuration digest)
`sha256:83fdfd593024d5992ae0018af7d806d5b2c28eb8f4682d803f0649a1f6b0c802`,
the configuration that manifest names, which a pull shows as the Id on
`overlay2`. Created 2026-08-10T18:17:02Z; Python 3.13.14. The creation time
and the Python were read from the image configuration in the registry,
without a pull. No GitHub Release exists for this tag.

abuseipdb-proxy 0.1.0 — first release
