# Build context expected at apps/mcps/google/ so the sibling _common/
# package is visible to the relative path-dep in ads/pyproject.toml.

FROM python:3.13-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

RUN useradd --create-home appuser

WORKDIR /app/ads

# Copy the shared package first so the path-dep resolves during sync.
COPY _common /app/_common
COPY ads/pyproject.toml ads/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY ads /app/ads
RUN chown -R appuser:appuser /app

# Pre-create the shared OAuth data dir so the named volume inherits
# appuser ownership on first mount.
RUN mkdir -p /data/google_oauth && chown -R appuser:appuser /data

USER appuser

EXPOSE 8000

CMD ["uv", "run", "google-ads-mcp"]
