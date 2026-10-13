# SentinelX / Risk Radar

SentinelX is a prototype for evidence-led investigation of possible brand impersonation and digital-risk reports. It accepts user-submitted URLs, text, social handles, app listings, and screenshots; compares identities with a locally configured brand registry; records evidence provenance; and presents explainable findings for analyst review. It is a triage aid, not a determination that a target is malicious. Optional providers, network access, and available evidence affect each result.

The introduction is at `/`, the implementation overview at `/project`, and the analyst application at `/app` (also `/dashboard`). The API uses the `/api/v1` prefix and FastAPI serves interactive OpenAPI documentation at `/docs`.

## What is implemented

- Brand profiles and registered official assets (domains, handles, names, and application identifiers), persisted in the configured database.
- Submission, normalization, deduplication, discovery, and evidence-analysis APIs. Supported evidence includes URLs/domains, text, social-profile handles, app-listing identifiers/URLs, and base64 image data URIs.
- URL/domain and text analyzers, brand-asset comparisons, Apple App Store metadata lookup, and Google Play identifier parsing. Google Play metadata lookup and authorized social-platform discovery are not implemented; social discovery reports unavailable unless an authorized connector is supplied.
- An official-asset exclusion gate, deterministic explainable rules, evidence correlation, case triage, analyst reviews, and an inline investigation summary with a completion dialog. The summary presents returned evidence, limitations, and provider failures; it does not create evidence when a stage fails or returns empty results.
- Optional Brave, Tavily, or Exa web search. `SEARCH_PROVIDER` selects one provider; the chosen provider needs its matching key. Results are metadata/snippets with source URLs and provenance. The application does not fetch arbitrary result pages, and no live provider test is implied by mocked adapter tests.
- Optional provider-backed investigation and retrieval-augmented analysis (RAG). APInex, Claude, Groq, OpenRouter, and Ollama-compatible chat providers are selectable through `LLM_PROVIDER`; no live model call is made by default. Claims are checked against retrieved source references. Search snippets remain unverified material.
- Image validation and decoding with Pillow, plus optional local Tesseract OCR through the `ocr` Python extra and an operator-installed Tesseract executable. Claude vision uses `ANTHROPIC_API_KEY` and `VISION_MODEL`; optional Groq vision uses `GROQ_API_KEY` and `GROQ_VISION_MODEL` with documented base64 data-URL input. Groq's currently documented vision model is Preview. OCR text and model observations retain separate provenance. APInex image input for uploaded bytes has not been confirmed, so APInex vision is not integrated.
- A logistic-regression ranking service and an offline synthetic evaluation benchmark. The ML service reports `no_model` until trained, and its outputs are ranking scores, not calibrated probabilities. Training metrics describe only the supplied dataset. No genuine labeled production dataset or production validation is included.
- Persisted monitoring targets, checks, and alerts. The in-process scheduler is disabled by default; source checks remain subject to configured providers and their availability.

These capabilities have different verification levels. Automated tests exercise local logic and mocked network responses; they do not establish current availability, quota, terms compliance, or accuracy of external services. The `POST /api/v1/demo/seed` endpoint inserts labeled demo records for UI walkthroughs; those records are illustrative and are not live threat intelligence or model-training validation.

## Investigation flow and architecture

FastAPI routes in `src/risk_radar/api/v1/` call focused services in `src/risk_radar/`. SQLAlchemy models and Alembic migrations provide persistence. Static HTML, CSS, and JavaScript under `src/risk_radar/static/` provide the introduction, overview, and analyst application; no frontend build step is configured.

The analyst UI submits evidence to Stage 5 analysis, evaluates the official-asset gate and rules, then requests risk scoring, RAG analysis, and investigator findings. The last three requests can settle independently; the UI updates its summary as results arrive and marks the final summary complete or incomplete after all settle. This UI workflow does not automatically run every API capability: ML training/scoring and evidence correlation are separate endpoints. Case management, analyst review, and periodic monitoring are separate persisted workflows.

Risk outputs are prioritization scores. The risk service combines rule-derived detection risk with an optional trained ML ranking and an impact multiplier when data is available; unavailable ML falls back to rules, and missing impact uses a neutral multiplier. This is not a probability of maliciousness. The gate remains authoritative for verified official or unverified identities. Rules report explicit matches, non-matches, skipped checks, reasons, and evidence references; missing inputs are not treated as matches.

RAG retrieves stored evidence and may use the selected search connector and configured language model. Claims and recommendations are returned only when they satisfy the service's evidence/citation checks; provider failure or absent credentials is represented as unavailable/partial with limitations. An AI-generated result is not independent verification. OCR, where configured, extracts image text locally; Claude image observations are separately labeled and unverified. Either can fail without fabricating image content.

## Local setup

Python 3.12 or newer is required. On Windows PowerShell:

```powershell
cd C:\path\to\Risk-Radar
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
$env:DATABASE_URL = "sqlite:///./risk_radar.db"
python -m uvicorn risk_radar.main:app --host 127.0.0.1 --port 8000
```

On macOS/Linux, use `python3.12 -m venv .venv`, activate with `source .venv/bin/activate`, then run the same installation and launch commands. The project creates its schema automatically when using SQLite. PostgreSQL deployments use Alembic migrations instead.

Open `http://127.0.0.1:8000/` for the introduction, `/app` for investigations and cases, `/project` for the technical overview, `/docs` for OpenAPI, or `/api/v1/health` for process liveness. To seed illustrative records, use the dashboard button or call `POST /api/v1/demo/seed`; `risk_radar.demo.seeder` is not a command-line entry point.

To run tests, install the `dev` extra as above and run:

```powershell
python -m pytest
node --test tests/test_investigation_summary.cjs
node --check src/risk_radar/static/app.js
node --check src/risk_radar/static/investigation_summary.js
git diff --check
```

The Python suite uses mocks for provider HTTP calls where applicable. Do not interpret a passing mocked test as a successful live integration. There is no frontend package manifest or bundler build. OCR tests that require Tesseract may skip when the optional binding or executable is unavailable. Run only the checks supported by the environment and report skipped or failed checks as such.

Verification snapshot from 2026-10-13: the full Python suite passed 424 tests with no skips when `TESSERACT_CMD` was set to the locally installed executable for that test process. The focused demo-case tests passed 4 tests, and the focused vision tests passed 54. The JavaScript summary suite passed 12 tests; both JavaScript syntax checks, Ruff, and `git diff --check` passed. Pytest emitted one Starlette deprecation warning for the current `TestClient`/`httpx` pairing. Browser verification showed the local dashboard loading backend counts and provider status, listing seven synthetic cases, and opening case detail and report data. No live provider calls were made.

## Optional OCR setup

Pillow is a required project dependency and validates/decodes supported images. OCR additionally requires the optional `pytesseract` binding and the separately installed Tesseract executable. Install the binding with `python -m pip install -e ".[ocr]"` (or install `.[dev,ocr]` for development). Install Tesseract using the operating-system package or installer; the Python package does not install the executable.

If Tesseract is not on `PATH`, set `TESSERACT_CMD` to its executable path, for example in PowerShell:

```powershell
$env:TESSERACT_CMD = "C:\Program Files\Tesseract-OCR\tesseract.exe"
```

When unset, the adapter keeps its normal `PATH` lookup. Image size, dimensions, format, and decoder checks still apply. Production OCR is not confirmed until the deployed runtime has both the binding and executable configured and verified.

## Configuration

Settings are loaded from environment variables and `.env` (case-insensitive). `.env.example` is a template, not a secret store; replace example credentials locally and never commit real secrets. All provider keys are optional unless that provider is selected. `GET /api/v1/providers/configuration` reports the selected search provider and key-presence booleans; it never returns key values.

| Variable names | Use |
| --- | --- |
| `DATABASE_URL` (alias `DATABASE_URL_ENV`) | Explicit SQLAlchemy URL; takes precedence over `POSTGRES_*`. Use SQLite for local single-process development. |
| `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD` | Build the PostgreSQL connection when `DATABASE_URL` is unset. |
| `REDIS_HOST`, `REDIS_PORT`, `REDIS_DB`, `REDIS_PASSWORD` | Redis connection settings used by infrastructure configuration. |
| `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, `MINIO_BUCKET`, `MINIO_SECURE` | Object-storage settings. The current evidence pipeline does not imply that every uploaded artifact is stored in MinIO. |
| `APP_NAME`, `APP_ENVIRONMENT` | API title and environment label. |
| `URLHAUS_AUTH_KEY` | Optional URLhaus authentication credential. |
| `SEARCH_PROVIDER`, `BRAVE_SEARCH_API_KEY`, `BRAVE_SEARCH_TIMEOUT_SECONDS`, `TAVILY_API_KEY`, `EXA_API_KEY`, `SEARCH_PROVIDER_TIMEOUT_SECONDS` | Select and configure one optional web-search connector (`brave`, `tavily`, or `exa`) and request timeouts. |
| `LLM_PROVIDER`, `LLM_MODEL`, `LLM_FALLBACK_PROVIDERS` | Select the investigator/RAG chat provider, model, and optional fallback order. Accepted providers are `apinex`, `claude`, `groq`, `openrouter`, `ollama`, or empty/unavailable. |
| `APINEX_API_KEY`, `APINEX_BASE_URL`, `APINEX_MODEL` | APInex chat configuration. Does not enable APInex uploaded-image analysis. |
| `ANTHROPIC_API_KEY`, `VISION_MODEL` | Claude chat credentials and configurable vision-capable model. The same Anthropic key is used by the Claude text/vision adapters. |
| `GROQ_API_KEY`, `GROQ_MODEL`, `GROQ_VISION_MODEL`, `OPENROUTER_API_KEY`, `OPENROUTER_MODEL` | Optional Groq chat and vision configuration (vision defaults to the currently documented Preview model), plus OpenRouter chat configuration. |
| `OLLAMA_BASE_URL`, `OLLAMA_MODEL` | Optional OpenAI-compatible local Ollama chat endpoint; no Ollama setup is bundled or required. |
| `TESSERACT_CMD` | Optional explicit path to the Tesseract executable for local OCR; otherwise the adapter searches `PATH`. |
| `EVIDENCE_ENABLE_LIVE_RESOLVERS`, `EVIDENCE_DNS_TIMEOUT_SECONDS`, `EVIDENCE_RDAP_TIMEOUT_SECONDS`, `EVIDENCE_RDAP_BOOTSTRAP_URL`, `EVIDENCE_ENABLE_REDIRECTS`, `EVIDENCE_REDIRECT_MAX_HOPS`, `EVIDENCE_REDIRECT_TIMEOUT_SECONDS` | Optional DNS/RDAP/redirect enrichment and limits. Network resolvers and redirects are disabled by default. |
| `MONITORING_SCHEDULER_ENABLED`, `MONITORING_SCHEDULER_POLL_SECONDS`, `MONITORING_SCHEDULER_BATCH_SIZE` | Opt-in bounded in-process monitoring scheduler; disabled by default. Use one scheduler-enabled application worker. |

Docker Compose also reads `API_PUBLISHED_PORT`, `POSTGRES_PUBLISHED_PORT`, `REDIS_PUBLISHED_PORT`, `MINIO_API_PUBLISHED_PORT`, and `MINIO_CONSOLE_PUBLISHED_PORT` for host port mappings. These are Compose variables rather than application settings.

## API routes

All API paths below are prefixed with `/api/v1`.

| Methods and paths | Purpose |
| --- | --- |
| `GET /health` | Process liveness only; does not verify database or provider health. |
| `POST /brands`, `GET /brands/{brand_id}`, `POST /brands/{brand_id}/assets`, `GET /brands/{brand_id}/assets` | Manage brands and official identity assets. |
| `POST /submissions`, `GET /submissions/{submission_id}` | Create and retrieve submitted evidence. |
| `POST /discover`, `POST /discover/social-profile` | Run configured discovery connectors or the authorized social-provider seam. |
| `POST /collect` | Normalize and deduplicate supplied candidates. |
| `POST /evidence/analyze` | Analyze supplied URL/text/image/app evidence. |
| `POST /gate/evaluate`, `GET /gate/audit` | Evaluate and inspect official-asset gate decisions. |
| `POST /rules/evaluate` | Run explainable deterministic rules. |
| `POST /risk/score` | Compute prioritization score and limitations. |
| `POST /rag/analyze`, `POST /investigate` | Retrieve/synthesize evidence and investigator findings. |
| `POST /ml/score`, `POST /ml/train` | Score or train the in-process ranking model using supplied labels. |
| `POST /correlate` | Correlate a supplied set of candidate references. |
| `POST /cases`, `GET /cases`, `GET /cases/{case_id}`, `PATCH /cases/{case_id}/status`, `POST /cases/{case_id}/events`, `GET /cases/{case_id}/report`, `GET /dashboard` | Case lifecycle and real dashboard counts/recent cases. |
| `POST /review`, `GET /review/history`, `GET /review/{review_id}`, `GET /feedback/labels` | Persist analyst review and retrieve review/feedback data. |
| `POST /demo/seed`, `GET /evaluation/benchmark` | Insert illustrative demo records and run the synthetic offline benchmark. |
| `GET /providers/configuration` | Return selected search provider and configured-key booleans. |
| `GET /monitoring/status`, `/monitoring/targets`, `/monitoring/targets/{target_id}`, `/monitoring/targets/{target_id}/checks`, `/monitoring/targets/{target_id}/checks/{check_id}`, `/monitoring/alerts` | Inspect monitoring runtime, targets, check history, and alerts. Target creation/checking use `POST`; target update/removal use `PATCH`/`DELETE`; alert acknowledgement uses `POST /monitoring/alerts/{alert_id}/acknowledge`. |

The full request and response schemas are available at `/docs` while the app is running.

## Docker Compose and deployment

The Docker image uses Python 3.12, installs the `ocr` extra and Tesseract executable, runs Alembic migrations at container startup, and starts Uvicorn on Render's `PORT` (or port 8000 when unset). Docker Compose defines the API, PostgreSQL, Redis, and MinIO services. Compose requires `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `MINIO_ACCESS_KEY`, and `MINIO_SECRET_KEY` in `.env`; replace the example values before use. The published-port variables are optional.

For a fresh Compose database, build the image, start its dependencies, apply migrations, then start the API:

```powershell
Copy-Item .env.example .env
docker compose build api
docker compose up -d postgres redis minio
docker compose run --rm --no-deps api alembic upgrade head
docker compose up -d api
```

The API startup creates tables automatically only for SQLite. PostgreSQL schema changes require `alembic upgrade head`; the Docker container runs this migration at startup, and the explicit Compose migration command above can be used to apply it before starting the API. The compose health route checks API liveness, not provider readiness. MinIO is configured in the stack, but its presence alone does not mean every evidence upload is persisted there.

No Render manifest or automated deployment workflow is present in this repository. The current production service uses Render's native Python runtime, which does not run the Dockerfile's Tesseract installation. To enable OCR, configure the existing service to use the root Dockerfile, retain its PostgreSQL connection through `DATABASE_URL` or `POSTGRES_*`, and preserve its required provider settings. The Docker container runs `alembic upgrade head` before starting Uvicorn; this keeps migrations in the startup path for Free services, where Render's separate pre-deploy command is unavailable. Verify the deployment and OCR behavior after switching; local OCR tests do not establish production behavior.

## Known limitations and verification status

- Search adapters, URLhaus/OpenPhish connectors, Apple lookup, and hosted models are optional. Mocked tests validate adapter behavior but no live provider success is claimed here.
- OpenPhish uses its public feed; URLhaus authentication is optional/configuration-dependent. Feed reachability, rate limits, and current service status depend on the deployment network and were not established by this documentation update.
- APInex is configured as a chat provider. Its documented image input currently supports public image URLs, while uploaded-byte/base64 support has not been confirmed; APInex vision is therefore not implemented.
- Claude vision requires `ANTHROPIC_API_KEY` and a supported `VISION_MODEL`. If Claude credentials are absent, Groq vision is selected when `GROQ_API_KEY` is configured; it uses `GROQ_VISION_MODEL` (default `qwen/qwen3.8-27b`), which Groq currently labels Preview. No live model call is implied. The UI may report provider unavailability or partial evidence.
- Local OCR needs Pillow, the optional `pytesseract` binding, and the Tesseract executable. Production OCR is unverified until deployment configuration is checked.
- No authorized social platform connector or Google Play metadata provider is configured. App-store lookup is Apple-only; parsing an identifier does not retrieve Google Play metadata.
- ML ranking is experimental until trained and evaluated using genuine, representative, labeled data. The supplied synthetic benchmark and example/demo data do not establish operational performance.
- The monitoring scheduler is opt-in, in-process, and intended to run on one enabled worker. Provider coverage remains limited by configured connectors.
- The repository contains no frontend build manifest. Browser verification, live provider checks, and deployment checks must be reported separately from unit tests.

For challenge scope and feature-by-feature status, see [docs/HACXLERATE_REQUIREMENTS.md](docs/HACXLERATE_REQUIREMENTS.md).
