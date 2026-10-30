# CLAUDE.md — abuseipdb-proxy

## Hard constraints (never violate)

- **Read-only upstream**: the service calls only the CHECK endpoint,
  `GET <base>/check`, at the configured base URL (default
  `https://api.abuseipdb.com/api/v2`; `ABUSEIPDB_BASE_URL` overrides it for
  tests and mocks) — never REPORT or any other mutating endpoint.
- **Localhost-only**: the port is published on `127.0.0.1` exclusively; no
  caller authentication, by design.
- **API key lives in the environment only** (`.env`, never committed;
  `SecretStr` in code; never logged, never echoed in responses).
- **`async def` is banned codebase-wide** — plain `def` endpoints plus
  `requests` with an explicit timeout on every upstream call (SPEC D7).
- **English only** for everything that lands in the repository.
- **Tests are offline**: no network, no key; upstream faked from
  `docs/research/captures/`. The network guard in conftest fails every
  connection; tests marked `loopback` may connect to numeric loopback
  addresses only (`127.0.0.0/8`, `::1`). Never widen it beyond that.
- **`docs/research/captures/` are frozen fixtures**: tests assert their
  exact values. Never overwrite an existing capture — a fresh capture gets a
  fresh file name.

## Source of truth

`docs/SPEC.md` (decisions D1–D9) governs all behavior; empirical evidence
lives in `docs/research/NOTES.md` (findings F1–F11) with raw captures next to
it. When touching behavior, cite the decision you are implementing.

## Workflows

- uv-first: `uv sync`, `uv run pytest -q`, `uv run ruff check .`,
  `uv run ruff format .`
- Run locally: `uv run uvicorn --factory abuseipdb_proxy.app:create_app --port 8000`
- Container must build with the classic builder — no BuildKit-only syntax in
  the Dockerfile (SPEC §8); CI enforces this.
- Release: the procedure is the Release section below (SPEC §8).
- Secret hygiene: gitleaks hooks are active via `core.hooksPath=.githooks`
  (per-clone setting); the CI gitleaks scan is the non-bypassable layer.

## Release

Every public step (push, tag) needs the maintainer's explicit word.

1. **Release commit** on `main`:
   - bump `version` in `pyproject.toml`, then run `uv lock`;
   - move the README's `docker pull` line to the new version;
   - add the `CHANGELOG.md` entry: the notes, with placeholders for the
     date, the digest, the image Id (configuration digest) and the Python.

   CI must be green on it.
2. **Tag:** an **annotated** `v<version>`, whose message is
   `abuseipdb-proxy <version>`, a blank line, then that entry's notes.
   - Build the message from the entry; never retype it.
   - Show the full text to the maintainer before tagging.
   - Compare the created tag's message with the text before pushing it.

   `release.yml` refuses a lightweight tag, or a tag that does not match
   `pyproject.toml`, before anything is built.
3. **The workflow:**
   - `publish` runs the suite on the tagged commit, builds with the classic
     builder and pushes `ghcr.io/janwychowaniak/abuseipdb-proxy:<version>`
     and `:latest` (public, linked to this repo).
   - Its step summary records the digest, the image Id (configuration
     digest) and the Python. The Id is read from the pushed manifest,
     because on the runner's containerd image store `docker image inspect`
     `.Id` is not the configuration digest.
   - `archive` pulls by digest and runs `.github/scripts/archive-image.sh`,
     which checks the archive's configuration digest against the record and
     proves the load.
   - It then creates the GitHub Release from the tag message, with
     `abuseipdb-proxy-<version>.tar.gz` and its `.sha256`, and checks that
     the release notes equal the tag message.
   - If `archive` fails, re-run that job alone.
4. **Afterwards:** read the run's log, then commit the date, digest, image
   Id and Python into the `CHANGELOG.md` entry on `main`.

**A tag is never pushed again, not even to fix its message.** Doing so
re-runs the release and can publish the same version under another digest;
a wrong line is corrected in `CHANGELOG.md` as an erratum.

The release path runs only on tags. A change to `release.yml` or
`archive-image.sh` is checked locally as far as it goes, then by reading
the next release's log.
