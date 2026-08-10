# CLAUDE.md — abuseipdb-proxy

## Hard constraints (never violate)

- **Read-only upstream**: the service calls only `GET /api/v2/check` on
  AbuseIPDB — never REPORT or any other mutating endpoint.
- **Localhost-only**: the port is published on `127.0.0.1` exclusively; no
  caller authentication, by design.
- **API key lives in the environment only** (`.env`, never committed;
  `SecretStr` in code; never logged, never echoed in responses).
- **`async def` is banned codebase-wide** — plain `def` endpoints plus
  `requests` with an explicit timeout on every upstream call (SPEC D7).
- **English only** for everything that lands in the repository.
- **Tests are offline**: no network, no key; upstream faked from
  `docs/research/captures/`. Never weaken the network guard in conftest.

## Source of truth

`docs/SPEC.md` (decisions D1–D8) governs all behavior; empirical evidence
lives in `docs/research/NOTES.md` (findings F1–F11) with raw captures next to
it. When touching behavior, cite the decision you are implementing.

## Workflows

- uv-first: `uv sync`, `uv run pytest -q`, `uv run ruff check .`,
  `uv run ruff format .`
- Run locally: `uv run uvicorn --factory abuseipdb_proxy.app:create_app --port 8000`
- Container must build with the classic builder — no BuildKit-only syntax in
  the Dockerfile (SPEC §8); CI enforces this.
- Secret hygiene: gitleaks hooks are active via `core.hooksPath=.githooks`
  (per-clone setting); the CI gitleaks scan is the non-bypassable layer.
