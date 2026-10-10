# Risk Radar v4 — Stage 10: Evidence Correlation

Project scaffold plus Stages 1-2 of the Risk Radar v4 architecture: service skeleton and infrastructure wiring (FastAPI liveness route, environment-backed settings, SQLAlchemy/Alembic setup, Docker Compose services), official brand profiles with their assets, and user submissions stored as raw evidence. Stage 3 adds discovery connectors. Later stages (detection, ML, cases) are not implemented yet.

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
├── api/v1/       # Versioned HTTP routes (health + brand intelligence)
├── cache/        # Redis integration boundary
├── core/         # Pydantic settings and shared configuration
├── db/           # SQLAlchemy base, session factory and domain models
├── storage/      # MinIO integration boundary
└── main.py       # FastAPI application
migrations/       # Alembic environment and revisions (0001_brand_intelligence)
tests/            # pytest suite
```

PostgreSQL settings, Redis host/port/database/password, and MinIO endpoint/credentials are loaded from environment variables. Stage 1 adds the first domain models (`Brand`, `BrandAsset`) and migration `0001_brand_intelligence`; Stage 2 adds `Submission` and migration `0002_user_submissions` (both in `src/risk_radar/db/models.py`).

## Brand intelligence API (Stage 1)

| Method | Route | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/brands` | Create an official brand profile (`{"name": "Acme"}`) |
| `GET` | `/api/v1/brands/{id}` | Read a brand profile |
| `POST` | `/api/v1/brands/{id}/assets` | Register an asset (`name`, `logo`, `account`, `application`, `domain`) with `verified` true/false |
| `GET` | `/api/v1/brands/{id}/assets` | List a brand's assets and their verification state |

## User submissions API (Stage 2)

| Method | Route | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/submissions` | Store raw evidence: `submission_type` (`url`, `message`, `screenshot`, `social_profile`, `app_listing`), `content`, optional `source` (default `user`) and optional `brand_id` |
| `GET` | `/api/v1/submissions/{id}` | Read a stored submission |

Every submission is persisted with an SHA-256 `content_hash`, its source, its type and a UTC timestamp. Type-specific validation returns `422` for mismatched content (for example a non-URL for the `url` type) and `404` for an unknown `brand_id`. Screenshots are stored as image URLs or base64 `data:image/...` URIs; the MinIO storage boundary is still a placeholder, so binary file upload to object storage is not implemented yet.

## Discovery API (Stage 3)

| Method | Route | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/discover` | Run discovery for `{"query": "..."}`; returns deduplicated candidates and per-connector failures |

All connectors implement one interface (`risk_radar.discovery.base.DiscoveryConnector`) and yield the same candidate record (`candidate_id`, `source`, `source_reference`, `candidate_type`, `target`, `discovered_at`, `metadata`, `provenance`). Connector status:

| Connector | Status |
| --- | --- |
| `urlhaus` | Functional; requires the optional `URLHAUS_AUTH_KEY` environment variable (reported as unavailable when unset) |
| `openphish` | Functional; public plain-text feed, no credentials |
| `web_search` | Interface only; no search provider configured |
| `social` | Interface only; no platform API credentials configured |
| `app_store` | Interface only; no listing source configured |

Aggregation isolates failures: an unavailable source is reported in `failures` without breaking the others. Candidates are deduplicated on a normalized target while preserving every source in `provenance`. Tests mock all external responses; no test performs network calls.

## Collection API (Stage 4)

| Method | Route | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/collect` | Normalize, validate and deduplicate `{"candidates": [...]}` into consistent records |

`risk_radar.collection.service.CollectionService` turns candidates from any source into one `CollectedRecord` shape: `record_id` (deterministic, from the cleaned target), `original_target` (raw evidence preserved), `normalized_target`, `sources` and `source_references` (all contributing sources), `provenance`, merged `metadata`, `collected_at`, and `validation_status` with `validation_errors`. URL cleaning lowercases scheme/host, drops default ports and fragments, and keeps userinfo, port, path and query. Malformed inputs and connector failures become structured `CollectionError` entries without interrupting the run; the layer performs no outbound URL fetching.

## Exclusion gate API (Stage 6)

| Method | Route | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/gate/evaluate` | Evaluate `{target, kind?, analysis?}` against official assets; returns the gate decision |
| `GET` | `/api/v1/gate/audit` | Recent recorded gate decisions (append-only audit log) |

Three outcomes: `verified_official` (excluded, `alert_eligible: false`, `next_stage: null`), `unverified` (routed to `verification`), `not_matched` (routed to `detection`). Every decision is written to `exclusion_audit_log` (migration `0003`). `analysis` accepts the teammate's Stage 5 `AnalyzerResult` v1.0 contract (branch `teammate/evidence-engine`) via `risk_radar.gate.contracts`; failed/unavailable analyzers contribute limitations, never a safe verdict. Stage 5 analyzers themselves are owned by the teammate and are NOT implemented here.

## Rule engine API (Stage 7)

| Method | Route | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/rules/evaluate` | Server-side gate check + deterministic rules for `{target, kind?, analysis?, candidate_ref?}` |

The engine re-runs the Stage 6 gate internally (clients cannot supply `alert_eligible`): `verified_official` → `excluded_verified_official` (no rules run), `unverified` → `routed_to_verification`, `not_matched` → `evaluated`; gate failure → `failed_closed` with no findings. Registry (documented thresholds in `risk_radar/rules/engine.py`): `lookalike_domain`, `username_similarity`, `ip_host`, `suspicious_url_structure`, `newly_registered_domain` (only with explicit WHOIS/RDAP age data), `logo_publisher_mismatch` (only with explicit analyzer evidence). Every matched finding carries `rule_id`, `severity`, `reason`, `evidence_refs`, `observed_value`/`expected_value`, supported `confidence` and `provenance`; missing data yields `skipped` notes, never matches. No new tables: findings reference existing evidence (`brand_asset:{id}`, `target`, `analysis`).

## ML engine API (Stage 8)

| Method | Route | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/ml/score` | Run rules + gate, then score with the trained model when available |
| `POST` | `/ml/train` → `POST /api/v1/ml/train` | Train on labeled feature rows; returns held-out ROC-AUC for model and rules-only baseline |

`risk_radar.ml` extracts fixed-order features from rule evaluations (severity counts, rule flags, confidences, evidence counts), scores with a reproducible `LogisticRegression` (`logreg-v1`, `random_state=42`, joblib persistence), and compares against the documented severity-weighted rules-only baseline on a stratified held-out split (ROC-AUC). **Data reality: no genuine labeled data exists in this repository yet** (analyst labels arrive with Stage 14, seeded data with Stage 15); until then scoring honestly returns `no_model`, and metrics computed on supplied/synthetic datasets are explicitly marked unvalidated for production. Stage 6 outranks ML: verified official → `excluded_verified_official`, unverified → `routed_to_verification`, never alert-eligible via ML; gate failure → fail closed.

## AI investigator API (Stage 9)

| Method | Route | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/investigate` | Read-only investigation of `{target, kind?, analysis?, candidate_ref?}` |

The investigator runs the Stage 6 gate first (verified official → `excluded_verified_official`, unverified → `routed_to_verification`, gate failure → `failed_closed`; the provider is never engaged), then two read-only tools — stored-evidence search (submissions, brand assets, audit log) and web research through the existing discovery connectors — and finally an optional LLM provider. Every factual finding must cite tool-produced sources; uncited findings or citations of unknown references are dropped. Retrieved web content is passed as untrusted data with an explicit prompt boundary (prompt-injection defense at the tool boundary). Provider setup (optional): `LLM_PROVIDER=claude`, `ANTHROPIC_API_KEY`, `LLM_MODEL`. Without credentials the status is `provider_unavailable` with tools still returning hits; Claude calls are unimplemented-live (never exercised in tests).

## Correlation API (Stage 10)

| Method | Route | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/correlate` | Correlate 2–100 candidates into campaign views with a timeline |

Supported signals (deterministic, documented strengths): `duplicate_content` (1.0), `shared_domain` same host (0.9) / same registrable domain (0.7), `shared_brand` via stored submissions (0.8), `shared_brand_token` (0.6). Every link states its reason and evidence refs; campaigns = connected components with direct links kept separate from `indirect_pairs`. Timelines use only real stored/provided timestamps (missing ones are counted, never faked). Unsupported and reported honestly: shared registrant (no WHOIS/RDAP data), shared logo publisher (needs Stage 5 analyzers). Stage 6 outranks correlation: verified official and unverified candidates never join campaigns or become alert-eligible; gate failure fails the request closed. No new tables.

The Docker image uses Python 3.12, and the Compose file starts the API, PostgreSQL, Redis, and MinIO together.
