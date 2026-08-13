# ---- build stage: resolve the locked environment with uv -------------------
# Classic-builder-compatible (SPEC §8): no RUN --mount, no heredocs,
# no COPY --link, no FROM --platform=. CI builds this with DOCKER_BUILDKIT=0
# to keep it that way.
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS builder

# bytecode for faster cold starts; never download a uv-managed interpreter —
# the venv must reference the same /usr/local python the runtime image has
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# dependency layer: cached until uv.lock/pyproject.toml change
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# project layer: --no-editable installs abuseipdb_proxy as a real wheel INTO
# the venv, so it is self-contained once copied out of this stage
# (README.md is here because pyproject's readme field needs it at wheel build)
COPY README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

# ---- runtime stage ---------------------------------------------------------
FROM python:3.13-slim-bookworm AS runtime

LABEL org.opencontainers.image.source="https://github.com/janwychowaniak/abuseipdb-proxy" \
      org.opencontainers.image.description="Read-only AbuseIPDB APIv2 CHECK reputation proxy" \
      org.opencontainers.image.licenses="MIT"

# non-root (SPEC §8): high UID avoids host-user collisions; the app never
# writes to disk (logs go to stdout), so 'app' needs no filesystem ownership
# beyond its venv
RUN useradd --create-home --uid 10001 app

WORKDIR /app
COPY --from=builder --chown=app:app /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

USER app
EXPOSE 8000

# 0.0.0.0 is container-internal only; the localhost-only guarantee lives in
# the compose/docker-run port mapping 127.0.0.1:...:8000 (SPEC §1).
# Single process, no --workers (SPEC §8): a config error must crash the
# container visibly. Access log off — the app's JSON request log supersedes it.
CMD ["uvicorn", "--factory", "abuseipdb_proxy.app:create_app", \
     "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
