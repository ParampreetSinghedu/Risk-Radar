# SentinelX / Risk Radar — Evidence-led brand-risk investigation

SentinelX / Risk Radar is a prototype for investigating potential brand impersonation across submitted URLs, domains, social profiles, app listings, and screenshots. It combines registered-brand comparisons, provenance-bearing evidence, explainable rules, optional model-assisted prioritization, persisted cases, and an opt-in monitoring lifecycle. Provider availability depends on configuration; an adapter or offline test does not imply live source verification. Findings support analyst review and are not proof of maliciousness.

The root route (`/`) is the user-facing introduction. The existing analyst dashboard is served at `/app` and `/dashboard`; the technical and verification overview is at `/project`.

---

## Architecture Overview

```text
                      [ External Threat Feeds ]       [ User Evidence Submissions ]
                       URLhaus / OpenPhish feeds           URL, Text, Screenshots
                                  │                                   │
                                  ▼                                   ▼
                           [ Stage 3: Discovery ]          [ Stage 2: Submissions ]
                                  │                                   │
                                  └───────────────┬───────────────────┘
                                                  ▼
                                       [ Stage 4: Collection ]
                                  (Normalize, Dedupe, Provenance)
                                                  │
                                                  ▼
                                  [ Stage 5: Multimodal Evidence ]
                             (URL, Domain, Text, Brand Profile, Vision)
                                                  │
                                                  ▼
                                  [ Stage 6: Official Exclusion Gate ]
                       ┌──────────────────────────┴──────────────────────────┐
                       │                                                     │
               [ Verified Official ]                                   [ Not Matched ]
            (EXCLUDED from alerts / safe)                                    │
                                                                             ▼
                                                                  [ Stage 7: Rule Engine ]
                                                              (6 Explainable Heuristics)
                                                                             │
                                              ┌──────────────────────────────┴──────────────────────────────┐
                                              ▼                                                             ▼
                                     [ Stage 8: ML Engine ]                                      [ Stage 9: AI Investigator ]
                                  (Logistic Regression Baseline)                               (Grounded Evidence + Web Tools)
                                              │                                                             │
                                              └──────────────────────────────┬──────────────────────────────┘
                                                                             ▼
                                                                 [ Stage 10: Correlation ]
                                                              (Campaign Graphs & Timelines)
                                                                             │
                                                                             ▼
                                                                 [ Stage 11: Risk × Impact ]
                                                               (Detection Risk × Business Impact)
                                                                             │
                                                                             ▼
                                                                  [ Stage 12: Grounded RAG ]
                                                               (Citation-Validated Synthesis)
                                                                             │
                                                                             ▼
                                                                 [ Stage 13: Case Triage ]
                                                               (Web Dashboard, Alerts, Reports)
                                                                             │
                                                                             ▼
                                                                 [ Stage 14: Human Review ]
                                                              (Audited Verdicts + Retraining Feedback)
                                                                             │
                                                                             ▼
                                                                [ Stage 15: Evaluation & Demo ]
                                                               (Repeatable Seeder & Benchmark)
```

---

## 17-Stage Pipeline Coverage Matrix

| Stage | Name | Status | Key Components & Files |
| :--- | :--- | :--- | :--- |
| **Stage 0** | Scaffold | **IMPLEMENTED & TESTED** | FastAPI app (`main.py`), health route (`/api/v1/health`), Pydantic settings, DB session with SQLite & Postgres support. |
| **Stage 1** | Brand Intelligence | **IMPLEMENTED & TESTED** | `Brand` and `BrandAsset` models, migration `0001`, verified domain/account/name assets, `/api/v1/brands`. |
| **Stage 2** | User Submissions | **IMPLEMENTED & TESTED** | `Submission` model, migration `0002`, SHA-256 deduplication, URL/screenshot validation, `/api/v1/submissions`. |
| **Stage 3** | Discovery | **IMPLEMENTED & TESTED** | URLhaus & OpenPhish live connectors, normalized candidate ingestion, provenance isolation, `/api/v1/discover`. |
| **Stage 4** | Collection Layer | **IMPLEMENTED & TESTED** | Multi-source normalization, URL canonicalization, deterministic record IDs, `/api/v1/collect`. |
| **Stage 5** | Multimodal Evidence | **IMPLEMENTED & TESTED** | Teammate analyzers (`app/analyzers/`), unified evidence service (`src/risk_radar/evidence/`), vision adapter (`vision.py`). |
| **Stage 6** | Exclusion Gate | **IMPLEMENTED & TESTED** | Server-side gate evaluation, fail-closed design, append-only `exclusion_audit_log`, `/api/v1/gate/evaluate`. |
| **Stage 7** | Rule Engine | **IMPLEMENTED & TESTED** | 6 deterministic explainable rules (`lookalike_domain`, `username_similarity`, `ip_host`, etc.), `/api/v1/rules/evaluate`. |
| **Stage 8** | ML Engine | **IMPLEMENTED & TESTED** | 14-dim feature vector, LogisticRegression baseline comparison, held-out ROC-AUC metrics, `/api/v1/ml/train`, `/score`. |
| **Stage 9** | AI Investigator | **IMPLEMENTED & TESTED** | Grounded multi-tool research (submissions, brand assets, audit logs, web feeds), prompt-injection defense, `/api/v1/investigate`. |
| **Stage 10** | Evidence Correlation| **IMPLEMENTED & TESTED** | Connected component graph clustering, campaign linkage, chronological timelines, `/api/v1/correlate`. |
| **Stage 11** | Risk × Impact | **IMPLEMENTED & TESTED** | Transparent formula (`0.6*rules + 0.4*ml`) * `business_impact`, non-probabilistic ranking, `/api/v1/risk/score`. |
| **Stage 12** | Grounded RAG | **IMPLEMENTED & TESTED** | Lexical retrieval over verified evidence, citation-validated synthesis, hallucination defense, `/api/v1/rag/analyze`. |
| **Stage 13** | Cases & Dashboard | **IMPLEMENTED & TESTED** | Case workflows (`open` -> `in_review` -> `closed`), alerts triage, single-page UI (`index.html`, `app.js`), `/api/v1/cases`. |
| **Stage 14** | Human Review | **IMPLEMENTED & TESTED** | Audited analyst verdicts (`malicious`, `benign`, `suspicious`), mandatory reason enforcement, retraining feedback labels. |
| **Stage 15** | Demo & Evaluation | **IMPLEMENTED & TESTED** | Repeatable idempotent seeder (`/api/v1/demo/seed`), 40-sample benchmark runner with precision/recall/F1/latency (`/api/v1/evaluation/benchmark`). |
| **Stage 16** | Final Deliverables | **IMPLEMENTED & TESTED** | Comprehensive docs, zero-dependency local setup, test verification records, and live demo script. |

---

## Quickstart & Launch Guide

### Option 1: Standalone Local Mode (Windows / macOS / Linux — Zero Docker Required)

This mode runs the entire stack using SQLite in local development without needing PostgreSQL or Docker.

1. **Clone & enter repository:**
   ```powershell
   cd Risk-Radar
   ```

2. **Create and activate Python virtual environment:**
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```powershell
   python -m pip install --upgrade pip
   python -m pip install -e ".[dev]"
   ```

4. **Launch the application:**
   ```powershell
   $env:DATABASE_URL="sqlite:///./risk_radar.db"
   python -m uvicorn risk_radar.main:app --port 8000 --host 127.0.0.1
   ```

5. **Open SentinelX in your browser:**
   Navigate to [http://localhost:8000](http://localhost:8000) for the introduction, [http://localhost:8000/app](http://localhost:8000/app) for the analyst dashboard, or [http://localhost:8000/project](http://localhost:8000/project) for the technical overview.

6. **Seed Demo Data with 1 Click:**
   Click the **⚡ Seed Demo Data** button in the dashboard header or run:
   ```powershell
   python -m risk_radar.demo.seeder
   ```

---

### Option 2: Docker Compose (Full Stack with PostgreSQL, Redis, MinIO)

```bash
cp .env.example .env
docker compose up --build
```
| Service | Address |
| :--- | :--- |
| **Introduction** | <http://localhost:8000/> |
| **Web Dashboard** | <http://localhost:8000/app> |
| **Technical Overview** | <http://localhost:8000/project> |
| **API Health** | <http://localhost:8000/api/v1/health> |
| **Interactive Docs** | <http://localhost:8000/docs> |
| **MinIO Console** | <http://localhost:9001> |

---

## Environment Variables Reference

All credentials and endpoints are read cleanly from environment variables or `.env`. No hardcoded secrets exist.

| Variable | Default (Local) | Purpose |
| :--- | :--- | :--- |
| `DATABASE_URL` | *None* (builds Postgres URL) | Set to `sqlite:///./risk_radar.db` for instant local development without Docker. |
| `POSTGRES_HOST` | `localhost` | PostgreSQL host for production / Docker Compose. |
| `POSTGRES_PORT` | `5432` | PostgreSQL port. |
| `POSTGRES_DB` | `risk_radar` | Database name. |
| `POSTGRES_USER` | `risk_radar` | Database username. |
| `POSTGRES_PASSWORD` | `local-only-change-me` | Database password. |
| `REDIS_HOST` | `localhost` | Redis server host. |
| `REDIS_PORT` | `6379` | Redis server port. |
| `MINIO_ENDPOINT` | `localhost:9000` | Object storage endpoint. |
| `URLHAUS_AUTH_KEY` | *None* | Optional API key for high-frequency URLhaus querying. |
| `BRAVE_SEARCH_API_KEY` | *None* | Optional Brave Search API subscription key for public web-result discovery and grounded search snippets. |
| `BRAVE_SEARCH_TIMEOUT_SECONDS` | `8.0` | Brave Search request timeout, bounded by the application to 0.5–15 seconds. |
| `SEARCH_PROVIDER` | `brave` | Selects exactly one hosted search adapter: `brave`, `tavily`, or `exa`. No hosted request is made unless the selected provider's key is configured. |
| `TAVILY_API_KEY` | *None* | Optional Tavily search API key; used only when `SEARCH_PROVIDER=tavily`. |
| `EXA_API_KEY` | *None* | Optional Exa search API key; used only when `SEARCH_PROVIDER=exa`. |
| `SEARCH_PROVIDER_TIMEOUT_SECONDS` | `8.0` | Timeout for the selected Tavily or Exa search request, bounded to 0.5–15 seconds. |
| `LLM_PROVIDER` | `""` | Optional LLM provider (`claude` or empty for graceful local fallback). |
| `ANTHROPIC_API_KEY` | *None* | Optional API key for Claude investigation and vision parsing. |
| `VISION_MODEL` | `claude-haiku-4-5-20251001` | Anthropic vision model ID, configured separately from the text LLM model. |

For local optional search, copy `.env.example` to the Git-ignored `.env`, set `SEARCH_PROVIDER` to the provider you intend to use, and add only that provider's key (`BRAVE_SEARCH_API_KEY`, `TAVILY_API_KEY`, or `EXA_API_KEY`). To enable Claude vision, set `ANTHROPIC_API_KEY`; choose the image model with `VISION_MODEL`. The `GET /api/v1/providers/configuration` endpoint reports configured-key booleans and the selected search provider only; it never returns key values. No provider request is made by the configuration endpoint.

---

## Complete API Reference (v1)

### Platform & Health
- `GET /api/v1/health` — Liveness health check (`{"status": "ok"}`).

### Brand Intelligence & Assets (Stage 1)
- `POST /api/v1/brands` — Register official brand profile.
- `GET /api/v1/brands/{id}` — Retrieve brand details.
- `POST /api/v1/brands/{id}/assets` — Register official asset (domain, handle, logo, name) with verified flag.
- `GET /api/v1/brands/{id}/assets` — List official brand assets.

### Evidence Submissions (Stage 2)
- `POST /api/v1/submissions` — Ingest raw evidence payload (URL, text, screenshot URI) with SHA-256 deduplication.
- `GET /api/v1/submissions/{id}` — Read raw submission.

### Discovery & Collection (Stages 3 & 4)
- `POST /api/v1/discover` — Execute discovery across threat feeds (URLhaus, OpenPhish) with provenance isolation.
- `POST /api/v1/collect` — Normalize and deduplicate candidate records.

### Multimodal Evidence Engine (Stage 5)
- `POST /api/v1/evidence/analyze` — Run multimodal analysis across URL, brand profile, text, and image adapters.

### Exclusion Gate (Stage 6)
- `POST /api/v1/gate/evaluate` — Evaluate target against official brand assets (`verified_official`, `unverified`, `not_matched`).
- `GET /api/v1/gate/audit` — Append-only audit history of gate decisions.

### Rule Engine (Stage 7)
- `POST /api/v1/rules/evaluate` — Evaluate 6 deterministic explainable heuristic rules.

### Machine Learning Engine (Stage 8)
- `POST /api/v1/ml/score` — Score candidate features with LogisticRegression model.
- `POST /api/v1/ml/train` — Train model on feature matrix; returns held-out ROC-AUC vs rules baseline.

### AI Grounded Investigator (Stage 9)
- `POST /api/v1/investigate` — Synthesize multi-source evidence with citation verification.

### Evidence Correlation (Stage 10)
- `POST /api/v1/correlate` — Graph connected components campaign analysis and timeline reconstruction.

### Risk × Impact Engine (Stage 11)
- `POST /api/v1/risk/score` — Compute transparent composite score (`detection_risk * business_impact`).

### Grounded RAG (Stage 12)
- `POST /api/v1/rag/analyze` — Lexical evidence retrieval with claim-level citation validation.

### Cases, Dashboard & Alerts (Stage 13)
- `POST /api/v1/cases` — Open new investigation case with gate-authorized alert eligibility.
- `GET /api/v1/cases` — List and filter cases (`open`, `in_review`, `closed`).
- `GET /api/v1/cases/{id}` — Retrieve case and analyst event history.
- `PATCH /api/v1/cases/{id}/status` — Transition case workflow state.
- `POST /api/v1/cases/{id}/events` — Append analyst note or decision event.
- `GET /api/v1/cases/{id}/report` — Assemble formatted triage report.
- `GET /api/v1/dashboard` — Aggregate metrics and recent triage records.
- `GET /api/v1/alerts` — Retrieve active alert-eligible cases.

### Human Review & Feedback (Stage 14)
- `POST /api/v1/review` — Record audited analyst verdict (`malicious`, `benign`, `suspicious`) with mandatory reason.
- `GET /api/v1/review/history` — Audit trail of all human review decisions.
- `GET /api/v1/review/{id}` — Retrieve review details.
- `GET /api/v1/feedback/labels` — Retrieve structured feedback labels and 14-dim feature vectors for ML retraining.

### Demo & Evaluation (Stage 15)
- `POST /api/v1/demo/seed` — Idempotently seed official brands, assets, submissions, cases, and reviews.
- `GET /api/v1/evaluation/benchmark` — Run offline benchmark evaluating accuracy, precision, recall, F1, and latency.

---

## Test Verification & Linting Results

All 230 automated unit and integration tests execute cleanly in under 4 seconds.

```powershell
pytest
```
```text
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.1.1, pluggy-1.6.0
rootdir: Risk-Radar
collected 230 items

tests\test_brand_profile_analyzer.py .                                   [  0%]
tests\test_brands.py .......                                             [  3%]
tests\test_cases.py ..................                                   [ 11%]
tests\test_collection.py ............                                    [ 16%]
tests\test_correlation.py .............                                  [ 22%]
tests\test_demo.py ...                                                   [ 23%]
tests\test_discovery.py .............                                    [ 29%]
tests\test_evaluation.py ..                                              [ 30%]
tests\test_evidence.py .......................                           [ 40%]
tests\test_gate.py ...........                                           [ 44%]
tests\test_health.py .                                                   [ 45%]
tests\test_image_analyzer.py .                                           [ 45%]
tests\test_investigator.py ..............                                [ 51%]
tests\test_ml.py ..............                                          [ 57%]
tests\test_rag.py .......................                                [ 67%]
tests\test_review.py ....                                                [ 69%]
tests\test_risk.py .................                                     [ 76%]
tests\test_rules.py .................                                    [ 84%]
tests\test_settings.py .                                                 [ 84%]
tests\test_submissions.py ...............                                [ 91%]
tests\test_text_analyzer.py .                                            [ 91%]
tests\test_url_analyzer.py .                                             [ 92%]
tests\test_vision.py ..................                                  [100%]

======================= 230 passed, 1 warning in 3.51s ========================
```

### Static Analysis & Formatting
```powershell
ruff check .
ruff format --check .
```
```text
All checks passed!
105 files already formatted.
```

---

## 3-Minute Live Demo Walkthrough for Judges

1. **Start the application:**
   ```powershell
   $env:DATABASE_URL="sqlite:///./risk_radar.db"
   python -m uvicorn risk_radar.main:app --port 8000
   ```
2. **Open the Web UI:**
   Navigate to [http://localhost:8000](http://localhost:8000).
3. **Populate Demo Data:**
   Click the **⚡ Seed Demo Data** button in the top navigation bar. Notice the instant population of:
   - Official brand profiles (PayPal, Microsoft, Acme Bank) and verified domain/asset registries.
   - Raw threat submissions from URLhaus feeds and user reports.
   - Live triage cards across `Open`, `In Review`, and `Closed` states.
4. **Live Pipeline Investigation:**
   - Click the **Investigate** tab.
   - Enter `https://paypal-security-update.com/login` and click **Run pipeline**.
   - Observe the step-by-step pipeline execution:
     - **Stage 6 Exclusion Gate:** Checks against official assets. Outcome: `not_matched` (alert-eligible).
     - **Stage 7 Rule Engine:** Evaluates explainable heuristics (`lookalike_domain`, brand token containment).
     - **Stage 11 Risk × Impact:** Transparently computes detection risk multiplied by PayPal business impact.
5. **Audited Human Review & ML Feedback Loop (Stage 14):**
   - Click the **Reviews & Feedback** tab.
   - Review an open case, enter a mandatory reason (e.g., *"Confirmed lookalike domain with credential harvesting form"*), and select `Malicious`.
   - Submit the verdict. The audit trail records the decision and automatically extracts the 14-dimensional feature vector.
   - Click **Trigger Retraining with Labels** to retrain the Stage 8 machine learning model with the human-labeled dataset.
6. **Benchmark & Evaluation (Stage 15):**
   - Click the **Evaluation** tab.
   - Click **Run Benchmark**. View live computed accuracy, precision, recall, F1-score, and latency metrics across 40 evaluation samples.
