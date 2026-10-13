FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md alembic.ini ./
COPY migrations ./migrations
COPY src ./src
COPY app ./app
RUN apt-get update \
    && apt-get install --no-install-recommends -y tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir ".[ocr]"

EXPOSE 8000

CMD ["sh", "-c", "alembic upgrade head && exec uvicorn risk_radar.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
