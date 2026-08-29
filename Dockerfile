# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --system app && useradd --system --gid app app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install .

COPY migrations ./migrations
COPY alembic.ini ./
COPY policies ./policies

USER app

EXPOSE 8080

# One image, three fail-closed processes; the entrypoint is chosen by the
# orchestrator command:
#   taxstamps-api        HTTP API (default)
#   taxstamps-consumer   declarations.* Kafka consumer
#   taxstamps-outbox     transactional outbox -> Kafka publisher
CMD ["taxstamps-api"]
