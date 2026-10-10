# Risk Radar v4 — Stage 0 Scaffold

Minimal project scaffold for the Risk Radar v4 architecture. This stage contains only the service skeleton and infrastructure wiring: a FastAPI liveness route, environment-backed settings, SQLAlchemy/Alembic setup, and Docker Compose services. It does not implement brand intelligence or later-stage behavior.

## Requirements

- Docker Engine with the Docker Compose v2 plugin
- Python 3.12+ for local development and tests

## Start the stack

Create the local environment file from the template, then start every service with Compose:

```bash
cp .env.example .env
docker compose up --build
```

The `.env.example` values are for local development only. Change the passwords in `.env` before exposing the stack. The API waits until PostgreSQL, Redis, and MinIO report healthy.

| Service | Local address | Notes |
| --- | --- | --- |
| FastAPI | <http://localhost:8000/api/v1/health> | Returns `{"status":"ok"}` |
| PostgreSQL | `localhost:5432` | Credentials and database name are in `.env` |
| Redis | `localhost:6379` | Password-protected; see `.env` |
| MinIO API | <http://localhost:9000> | Credentials are in `.env` |
| MinIO console | <http://localhost:9001> | Uses the MinIO credentials from `.env` |

Compose defines health checks for the API, PostgreSQL, Redis, and MinIO. The API health route is a liveness check only; it does not claim that application-level database, cache, or object-storage operations have been implemented.

Stop the stack with `docker compose down`. Named volumes preserve service data; `docker compose down -v` removes that data as well.

## Local development and verification

The API health test does not require running the infrastructure services. With Python 3.12+:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
pytest
ruff check .
ruff format --check .
```

## Project layout

```text
src/risk_radar/
├── api/v1/       # Versioned HTTP routes (health only at Stage 0)
├── cache/        # Redis integration boundary
├── core/         # Pydantic settings and shared configuration
├── db/           # SQLAlchemy base and session factory
├── storage/      # MinIO integration boundary
└── main.py       # FastAPI application
migrations/       # Alembic environment and empty revisions directory
tests/            # pytest suite
```

PostgreSQL settings, Redis host/port/database/password, and MinIO endpoint/credentials are loaded from environment variables. SQLAlchemy's declarative base and session factory plus Alembic's environment are present as scaffolding; no domain models or migrations are included yet. The Docker image uses Python 3.12, and the Compose file starts the API, PostgreSQL, Redis, and MinIO together.
