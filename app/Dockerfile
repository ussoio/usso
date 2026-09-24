# FROM ghcr-io.docker.kubit.dev/astral-sh/uv:python3.13-bookworm-slim AS fast-uv
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS fast-uv

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

COPY pyproject.toml uv.lock ./

RUN uv sync --frozen --no-dev --no-install-project


FROM python:3.13-slim AS fast-server

WORKDIR /app
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
COPY --from=fast-uv /app/.venv /app/.venv

RUN addgroup --system --gid 1000 user \
    && adduser --system --uid 1000 --ingroup user --disabled-password --gecos '' --home /home/user user \
    # && mkdir -p /home/user \
    # && chown -R user:user /home/user \
    && mkdir -p /app/logs \
    && chown -R user:user /app/logs

USER user
COPY --chown=user:user . .

CMD [ "python", "main.py" ]
