# Multi-stage uv build, classic-builder-compatible (SPEC §8): no RUN --mount,
# no heredocs, no COPY --link, no FROM --platform=. CI builds this with
# DOCKER_BUILDKIT=0 to keep it that way.

FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS builder
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
# --no-editable: install the project as a real wheel into the venv, so the
# venv is self-contained once copied out of this stage.
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.13-slim-bookworm
LABEL org.opencontainers.image.source="https://github.com/janwychowaniak/abuseipdb-proxy" \
      org.opencontainers.image.description="Read-only AbuseIPDB APIv2 CHECK reputation proxy" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"
EXPOSE 8000
# Single process, no --workers (SPEC §8): a config error must crash the
# container visibly. Access log off — the app's JSON request log supersedes it.
CMD ["uvicorn", "--factory", "abuseipdb_proxy.app:create_app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
