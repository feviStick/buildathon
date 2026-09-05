# Riskora local handoff

Run `./start-riskora.ps1` from PowerShell, then open http://localhost:8000.

LIVE starts empty and accepts events from Transactions. DEMO runs isolated scenarios and never mixes with LIVE. MongoDB configuration is in `backend/.env`; the current starter uses a memory fallback so the UI works even before MongoDB is installed or running.
