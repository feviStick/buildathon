# Riskora

A local payment risk intelligence console for the Razorpay Buildathon. It includes a polished dark operations UI, live ingestion, demo simulations, explainable risk scoring, model metrics, and health status.

## Run locally

Requirements: Python 3.10+.

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn server:app --reload --port 8000
```

Open http://localhost:8000. MongoDB is optional for this starter: the app uses an in-memory store so the demo works immediately. To connect MongoDB, copy `backend/.env.example` to `backend/.env` and run MongoDB locally; persistence can then be added to the repository layer.

The dashboard starts in LIVE mode with an empty state. Use Transactions to ingest a live event, or switch to DEMO and run Legitimate Growth, Coordinated Fraud, Fraud Escalation, or Cash-out scenarios. Demo data is cleared and isolated from live data.
