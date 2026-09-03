FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SPECTRE_DATA_DIR=/app/data \
    SPECTRE_REPORTS_DIR=/app/reports \
    SPECTRE_LOGS_DIR=/app/logs

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md alembic.ini ./
COPY spectre_osint ./spectre_osint

RUN pip install --no-cache-dir .

RUN mkdir -p /app/data /app/reports /app/logs \
    && useradd --create-home --uid 1000 spectre \
    && chown -R spectre:spectre /app

USER spectre

# .env is never copied into the image. Mount it at runtime if needed.
ENTRYPOINT ["spectre"]
CMD ["--help"]
