# Riskora API

FastAPI also exposes interactive documentation at `/docs` and `/redoc` when the local server is running.

## Core routes

- `GET /api/` health-shaped product response
- `GET /api/overview?mode=live|demo` mode-scoped dashboard overview
- `GET /api/transactions?mode=live|demo` list mode-scoped transactions
- `POST /api/transactions` ingest one LIVE transaction; duplicate IDs return `409`
- `GET /api/transactions/{transaction_id}?mode=live|demo` retrieve one transaction
- `POST /api/simulation/scenario` run a validated synthetic scenario
- `GET /api/entities/{entity_id}/network?mode=live|demo` relationship graph data
- `GET /api/transactions/{transaction_id}/money-trail?mode=live|demo` observable digital movement
- `GET /api/investigations?mode=live|demo` investigation records
- `POST /api/investigations/{investigation_id}/outcome` record a verified analyst outcome
- `GET /api/model/metrics` calculated held-out synthetic evaluation
- `GET /api/model/drift` drift watch status based on verified labels
- `GET /api/system/health?mode=live|demo` operational status

## Contracts and limits

Requests are validated with Pydantic. Transaction amounts must be positive, counters are bounded, scenario names are allow-listed, and analyst outcomes are limited to `CONFIRMED FRAUD`, `LEGITIMATE`, or `UNCERTAIN`. API clients are rate-limited to 120 requests per minute per client address. The limit is a prototype safeguard, not production authentication or abuse prevention.

LIVE is API-only and starts empty. DEMO is synthetic and reset per scenario. Both modes use the same scoring path. MongoDB is used when reachable; the explicit in-memory fallback keeps local judging possible without MongoDB.
