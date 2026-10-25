# ai-devops-assistant image: the exact code CI tested. Base images are pinned by digest;
# Dependabot (docker ecosystem) proposes bumps. Runs as a non-root user, no shell entrypoint.

FROM ghcr.io/astral-sh/uv:0.13.5@sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff AS uv

FROM python:3.14.7-slim-trixie@sha256:51dafde81dbdb6ebde285137a295cf18a47ca95234fe388a343719cb97305b3d AS build
COPY --from=uv /uv /uvx /bin/
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /app

# Dependencies first (cached layer), strictly from the committed lockfile.
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --frozen --no-dev --no-install-project

COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.14.7-slim-trixie@sha256:51dafde81dbdb6ebde285137a295cf18a47ca95234fe388a343719cb97305b3d AS runtime
LABEL org.opencontainers.image.title="ai-devops-assistant" \
      org.opencontainers.image.description="Rules-first AI assistant for CI failure triage, Kubernetes diagnosis and Terraform plan review" \
      org.opencontainers.image.source="https://github.com/rsk071216-stack/ai-devops-assistant" \
      org.opencontainers.image.licenses="MIT"

RUN groupadd --system --gid 10001 aida \
 && useradd --system --uid 10001 --gid aida --home-dir /home/aida --create-home \
      --shell /usr/sbin/nologin aida

COPY --from=build --chown=10001:10001 /opt/venv /opt/venv

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER 10001:10001
WORKDIR /home/aida
# A short-lived CLI has no port to probe.
HEALTHCHECK NONE
ENTRYPOINT ["aida"]
CMD ["--help"]
