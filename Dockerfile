# syntax=docker/dockerfile:1.7

# Multi-stage build:
#   uv_source -> safe source of /uv and /uvx binaries (no curl, no installer)
#   builder   -> resolve uv.lock into /app/.venv
#   runtime   -> copy only the venv and app/, no build tools, no uv
#
# Base image pinned by manifest-list digest. On WSL ARM64 the index resolves
# to the linux/arm64/v8 child; on the Debian VM it resolves to linux/amd64.
# Same Dockerfile, native build on each host, no --platform.
#
# Refresh procedure (only on a deliberate security bump):
#   docker buildx imagetools inspect python:3.12-slim
#   docker buildx imagetools inspect ghcr.io/astral-sh/uv:0.13.6
#   update both ARGs, rebuild both arches, re-run 8.1 validation
#
# Current pins (verified 2026-10-29):
#   python:3.12-slim                index -> amd64 + arm64 (both 3.12.16-slim-trixie)
#   ghcr.io/astral-sh/uv:0.13.6     index -> amd64 + arm64

ARG PYTHON_IMAGE=python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.13.6@sha256:af22a52f5eafef3d78e551599d405c02df61919d18028f0cea8eda93bc9986d0

# ---------- Stage: uv binaries source ----------
# COPY --from=<image-ref> does not perform ARG substitution at parse time; the
# reference is treated as a literal stage/context/image name. Using an
# intermediary FROM stage keeps the digest centralised in the ARG above and
# lets COPY --from reference a plain stage name instead.
FROM ${UV_IMAGE} AS uv_source

# ---------- Stage 1: builder ----------
FROM ${PYTHON_IMAGE} AS builder

COPY --from=uv_source /uv /uvx /usr/local/bin/

WORKDIR /app

# Dependencies first so the layer is cached until a dependency file changes.
COPY pyproject.toml uv.lock .python-version ./

# --locked             : fail the build if uv.lock disagrees with pyproject.toml
# --no-dev             : runtime deps only (no pytest, mypy, ruff, httpx)
# --no-install-project : tls-checker has no [build-system]; skip installing it.
#                        In-container imports of app.* work via cwd=/app.
RUN uv sync --locked --no-dev --no-install-project

COPY app ./app

# ---------- Stage 2: runtime ----------
FROM ${PYTHON_IMAGE} AS runtime

WORKDIR /app

COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/app /app/app

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]


# No HEALTHCHECK here; compose-level health check is Phase 8.3.
# No USER directive here; non-root user is Phase 8.2.
