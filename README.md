# Riskora

A local payment risk intelligence console for the Razorpay Buildathon. It includes a dark operations UI, LIVE API-only ingestion, isolated DEMO simulations, explainable risk scoring, timeline and entity graphs, observable money trails, investigations, calculated model metrics, drift monitoring, and health status.

## Run locally

Requirements: Python 3.10+ for local mode, or Docker Desktop for Compose mode.

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
cd ..
uvicorn backend.server:app --reload --port 8000
```

Open http://localhost:8000. MongoDB is optional: the app uses MongoDB when reachable and reports an explicit in-memory fallback when it is not. Copy `backend/.env.example` to `backend/.env` for local configuration. Never commit `.env`.

## Docker

```powershell
docker compose up --build
```

This starts MongoDB and Riskora on http://localhost:8000. The repository includes a CI workflow at `.github/workflows/ci.yml` that runs compilation and API tests.

## Vercel

Import this repository into Vercel with the repository root as the project root. `vercel.json` routes requests through `api/index.py`, which exposes the FastAPI application and serves the existing frontend. Add `MONGO_URL` and `DB_NAME` in Vercel project settings when using a hosted MongoDB provider; without them, the app uses its explicit ephemeral memory fallback for prototype judging.

The dashboard starts in LIVE mode with an empty state. Use Transactions to ingest a live event, or switch to DEMO and run Legitimate Growth, Coordinated Fraud, Fraud Escalation, Cash-out, account takeover, international, and adversarial scenarios. Demo data is cleared and isolated from live data. The Overview graph is populated from synthetic DEMO relationships and remains honestly empty in LIVE until ingestion creates entities.

## Tests and API docs

```powershell
python -m pytest backend/tests
```

FastAPI interactive docs are available at `/docs`; the concise route contract is documented in [API.md](API.md).
