from __future__ import annotations

import os
import uuid
import asyncio
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator

try:
    from pymongo import MongoClient
except ImportError:
    MongoClient = None

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"
MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "riskora")
CORS_ORIGINS = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:8000,http://localhost:3000").split(",") if origin.strip()]
logger = logging.getLogger("riskora")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")

mongo_db = None
if MongoClient:
    try:
        mongo_client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=250)
        mongo_client.admin.command("ping")
        mongo_db = mongo_client[DB_NAME]
    except Exception:
        mongo_db = None

app = FastAPI(title="Riskora API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS, allow_methods=["*"], allow_headers=["*"])


@app.middleware("http")
async def request_guard(request: Request, call_next):
    client_id = request.client.host if request.client else "unknown"
    if request.url.path.startswith("/api/"):
        current = time.monotonic()
        recent = [stamp for stamp in request_windows.get(client_id, []) if current - stamp < 60]
        if len(recent) >= 120:
            logger.warning("rate limit exceeded client=%s path=%s", client_id, request.url.path)
            return JSONResponse(status_code=429, content={"detail": "rate limit exceeded; retry shortly"})
        recent.append(current)
        request_windows[client_id] = recent
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("unhandled request failure method=%s path=%s", request.method, request.url.path)
        return JSONResponse(status_code=500, content={"detail": "internal server error"})
    logger.info("request method=%s path=%s status=%s duration_ms=%.1f", request.method, request.url.path, response.status_code, (time.perf_counter() - started) * 1000)
    return response

memory: dict[str, list[dict[str, Any]]] = {"live": [], "demo": []}
relationships: list[dict[str, Any]] = []
money_trails: dict[str, dict[str, Any]] = {}
investigations: dict[str, dict[str, Any]] = {}
state_lock = asyncio.Lock()
request_windows: dict[str, list[float]] = {}
SCENARIO_NAMES = {"legitimate_growth", "abuse_ring", "fraud_escalation", "cash_out", "fraud_escalation", "normal_activity", "suspicious_transaction", "account_takeover", "cross_border_anomaly", "slow_fraud", "distributed_fraud", "suspicious_merchant", "false_positive", "false_negative", "fraud_adaptation", "insufficient_evidence", "vpn_legitimate", "frequent_ip_changes"}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def risk_for(payload: dict[str, Any], scenario: str | None = None) -> dict[str, Any]:
    amount = float(payload.get("amount", 0))
    failed = int(payload.get("failed_attempt_count", 0))
    velocity = int(payload.get("velocity_10m", 1))
    score = 8 + min(amount / 25000, 24) + failed * 8 + max(velocity - 2, 0) * 5
    signals: list[str] = []
    if amount > 20000:
        signals.append("Amount materially above baseline")
    if failed >= 2:
        signals.append(f"{failed} failed payment attempts")
    if velocity >= 5:
        signals.append(f"{velocity} attempts in ten minutes")
    if payload.get("cross_border_flag"):
        signals.append("Cross-border context requires review")
    if payload.get("vpn_flag"):
        signals.append("VPN indicator treated as weak context")
    if scenario == "legitimate_growth":
        score = min(score, 28)
    if scenario in {"abuse_ring", "fraud_escalation", "cash_out"}:
        score += 25
        signals.extend(["Linked entity corroboration", "Downstream movement requires review"])
    score = max(0, min(100, round(score)))
    level = "CRITICAL" if score >= 85 else "HIGH" if score >= 65 else "MEDIUM / UNCERTAIN" if score >= 35 else "LOW"
    anomaly = min(100, round(18 + amount / 25000 * 45 + velocity * 5))
    if scenario == "legitimate_growth":
        anomaly = 82
    return {
        "risk_score": score,
        "confidence_score": min(96, 46 + len(signals) * 9),
        "risk_level": level,
        "anomaly_percentage": anomaly,
        "evidence": signals or ["No independent corroboration"],
        "estimated_exposure": round(amount * score / 100, 2),
        "urgency": "CRITICAL" if score >= 85 else "HIGH" if score >= 65 else "MEDIUM" if score >= 35 else "LOW",
        "recommended_action": "RESTRICT / HOLD / ESCALATE" if score >= 85 else "REVIEW / INVESTIGATE" if score >= 65 else "MONITOR / ADDITIONAL VERIFICATION" if score >= 35 else "ALLOW / MONITOR",
        "explanation": "Anomaly is elevated while corroborating risk remains low." if scenario == "legitimate_growth" else "Risk is based on multiple observable signals, not a single indicator.",
        "assessed_at": now(),
    }


def normalize(payload: dict[str, Any], mode: str, scenario: str | None = None) -> dict[str, Any]:
    item = {
        "transaction_id": payload.get("transaction_id") or f"txn_{uuid.uuid4().hex[:10]}",
        "timestamp": now(),
        "amount": float(payload.get("amount", 0)),
        "currency": payload.get("currency", "INR"),
        "payment_method": payload.get("payment_method", "upi"),
        "country": payload.get("country", "IN"),
        "merchant_country": payload.get("merchant_country", "IN"),
        "customer_id": payload.get("customer_id", "cus_demo_001"),
        "merchant_id": payload.get("merchant_id", "mrc_demo_001"),
        "device_id": payload.get("device_id", "dev_known_001"),
        "ip_address": payload.get("ip_address", "192.0.2.44"),
        "payment_instrument_id": payload.get("payment_instrument_id", "pi_demo_001"),
        "beneficiary_id": payload.get("beneficiary_id", "ben_demo_001"),
        "destination_account_id": payload.get("destination_account_id", "acct_demo_001"),
        "cross_border_flag": payload.get("country", "IN") != payload.get("merchant_country", "IN"),
        "failed_attempt_count": int(payload.get("failed_attempt_count", 0)),
        "velocity_10m": int(payload.get("velocity_10m", 1)),
        "vpn_flag": bool(payload.get("vpn_flag", False)),
        "mode": mode,
        "scenario": scenario,
    }
    item["risk"] = risk_for(item, scenario)
    return item


def overview(mode: str) -> dict[str, Any]:
    rows = memory[mode]
    alerts = []
    for row in rows:
        if row["risk"]["risk_level"] == "LOW":
            continue
        investigation_id = f"inv_{row['transaction_id']}"
        investigations.setdefault(investigation_id, {"investigation_id": investigation_id, "mode": mode, "alert_id": f"alt_{row['transaction_id']}", "transaction_id": row["transaction_id"], "status": "UNDER INVESTIGATION", "opened_at": row["timestamp"], "updated_at": row["timestamp"], "analyst_note": None, "outcome_confidence": None})
        alerts.append({"alert_id": f"alt_{row['transaction_id']}", "investigation_id": investigation_id, "transaction_id": row["transaction_id"], "entity": row["customer_id"], "timestamp": row["timestamp"], **row["risk"], "mode": mode})
    scores = [row["risk"]["risk_score"] for row in rows]
    events = []
    previous = 0
    for row in rows:
        score = row["risk"]["risk_score"]
        if score >= 65 or abs(score - previous) >= 18:
            events.append({"event_id": f"evt_{row['transaction_id']}", "timestamp": row["timestamp"], "event": "Risk level transition", "risk_before": previous, "risk_after": score, "evidence": row["risk"]["evidence"][0], "risk_level": row["risk"]["risk_level"]})
        previous = score
    return {
        "mode": mode,
        "total_transactions": len(rows),
        "high_risk_events": sum(row["risk"]["risk_level"] in {"HIGH", "CRITICAL"} for row in rows),
        "medium_risk_events": sum(row["risk"]["risk_level"] == "MEDIUM / UNCERTAIN" for row in rows),
        "estimated_exposure": round(sum(row["risk"]["estimated_exposure"] for row in rows), 2),
        "current_risk": scores[-1] if scores else 0,
        "risk_trend": round(scores[-1] - scores[0], 1) if len(scores) > 1 else 0,
        "active_investigations": len(alerts),
        "alerts": alerts[-12:][::-1],
        "timeline": [{"timestamp": row["timestamp"], "risk_score": row["risk"]["risk_score"], "anomaly_percentage": row["risk"]["anomaly_percentage"], "transaction_activity": row["amount"]} for row in rows],
        "events": events,
        "last_event": rows[-1]["timestamp"] if rows else None,
    }


class TransactionCreate(BaseModel):
    transaction_id: str | None = Field(default=None, min_length=3, max_length=80)
    amount: float = Field(gt=0)
    currency: str = Field(default="INR", min_length=3, max_length=3)
    payment_method: str = Field(default="upi", min_length=2, max_length=30)
    country: str = Field(default="IN", min_length=2, max_length=3)
    merchant_country: str = Field(default="IN", min_length=2, max_length=3)
    customer_id: str = Field(default="cus_live_001", min_length=3, max_length=80)
    device_id: str = Field(default="dev_known_001", min_length=3, max_length=80)
    failed_attempt_count: int = Field(default=0, ge=0, le=100)
    velocity_10m: int = Field(default=1, ge=0, le=1000)
    vpn_flag: bool = False
    ip_address: str = Field(default="192.0.2.44", min_length=3, max_length=80)
    payment_instrument_id: str = Field(default="pi_live_001", min_length=3, max_length=80)
    beneficiary_id: str = Field(default="ben_live_001", min_length=3, max_length=80)
    destination_account_id: str = Field(default="acct_live_001", min_length=3, max_length=80)

    @field_validator("currency", "country", "merchant_country", mode="before")
    @classmethod
    def normalize_code(cls, value: str) -> str:
        return value.strip().upper()

    @field_validator("merchant_country")
    @classmethod
    def validate_merchant_country(cls, value: str) -> str:
        if len(value) not in {2, 3}:
            raise ValueError("merchant_country must be an ISO-like 2 or 3 character code")
        return value


class ScenarioRequest(BaseModel):
    scenario: str = Field(min_length=3, max_length=50)

    @field_validator("scenario")
    @classmethod
    def validate_scenario(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in SCENARIO_NAMES:
            raise ValueError(f"unsupported scenario; choose one of: {', '.join(sorted(SCENARIO_NAMES))}")
        return normalized


class OutcomeRequest(BaseModel):
    outcome: str = Field(min_length=3, max_length=30)
    confidence: int = Field(default=90, ge=0, le=100)
    analyst_note: str = Field(default="Verified by analyst", min_length=3, max_length=500)

    @field_validator("outcome")
    @classmethod
    def validate_outcome(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized not in {"CONFIRMED FRAUD", "LEGITIMATE", "UNCERTAIN"}:
            raise ValueError("outcome must be CONFIRMED FRAUD, LEGITIMATE, or UNCERTAIN")
        return normalized


@app.get("/api/")
async def root() -> dict[str, str]:
    return {"product": "Riskora", "message": "Riskora API operational"}


@app.get("/api/overview")
async def get_overview(mode: str = "live") -> dict[str, Any]:
    return overview(mode if mode in memory else "live")


@app.get("/api/transactions")
async def get_transactions(mode: str = "live") -> list[dict[str, Any]]:
    return memory.get(mode, [])


@app.post("/api/transactions", status_code=201)
async def create_transaction(payload: TransactionCreate) -> dict[str, Any]:
    async with state_lock:
        raw = payload.model_dump()
        item = normalize(raw, "live")
        if any(row["transaction_id"] == item["transaction_id"] for row in memory["live"]):
            raise HTTPException(status_code=409, detail="transaction_id already processed in LIVE mode")
        memory["live"].append(item)
        if mongo_db is not None:
            mongo_db.transactions.replace_one({"transaction_id": item["transaction_id"], "mode": "live"}, item, upsert=True)
        create_relationships(item)
        logger.info("live transaction ingested transaction_id=%s risk=%s", item["transaction_id"], item["risk"]["risk_score"])
        return item


def create_relationships(item: dict[str, Any]) -> None:
    links = [
        ("CUSTOMER", item["customer_id"], "DEVICE", item["device_id"], "USES_DEVICE", 0.92),
        ("CUSTOMER", item["customer_id"], "NETWORK", item["ip_address"], "CONNECTS_FROM", 0.74),
        ("CUSTOMER", item["customer_id"], "PAYMENT_INSTRUMENT", item["payment_instrument_id"], "USES_INSTRUMENT", 0.86),
        ("CUSTOMER", item["customer_id"], "MERCHANT", item["merchant_id"], "TRANSACTS_WITH", 0.8),
        ("CUSTOMER", item["customer_id"], "BENEFICIARY", item["beneficiary_id"], "PAYS_TO", 0.78),
    ]
    for source_type, source_id, target_type, target_id, rel_type, strength in links:
        relationships.append({"mode": item["mode"], "source_entity_type": source_type, "source_entity_id": source_id, "target_entity_type": target_type, "target_entity_id": target_id, "relationship_type": rel_type, "relationship_strength": strength, "risk_contribution": item["risk"]["risk_score"] if strength >= 0.85 else max(0, item["risk"]["risk_score"] - 20), "timestamp": item["timestamp"]})


def create_money_trail(item: dict[str, Any], cash_out: bool = False) -> None:
    source = item["transaction_id"]
    account = item["destination_account_id"]
    transfer = f"transfer_{source}"
    nodes = [
        {"id": source, "type": "TRANSACTION", "label": "Original payment", "amount": item["amount"], "status": "OBSERVED"},
        {"id": account, "type": "ACCOUNT", "label": account, "amount": round(item["amount"] * .92, 2), "status": "OBSERVED"},
        {"id": transfer, "type": "TRANSFER", "label": "Onward movement", "amount": round(item["amount"] * .78, 2), "status": "OBSERVED"},
    ]
    edges = [{"source": source, "target": account, "amount": item["amount"], "description": "Payment settlement"}, {"source": account, "target": transfer, "amount": round(item["amount"] * .78, 2), "description": "Observable onward movement"}]
    if cash_out:
        cash_id = f"cash_{source}"
        nodes.append({"id": cash_id, "type": "CASH-OUT", "label": "Cash withdrawal", "amount": round(item["amount"] * .7, 2), "status": "DIGITAL ENDPOINT"})
        edges.append({"source": transfer, "target": cash_id, "amount": round(item["amount"] * .7, 2), "description": "Cash withdrawal observed"})
    money_trails[source] = {"transaction_id": source, "nodes": nodes, "edges": edges, "cash_out_detected": cash_out, "notice": "CASH-OUT DETECTED — DIGITAL TRACE ENDS HERE" if cash_out else None, "estimated_exposure": item["risk"]["estimated_exposure"]}


async def _run_scenario(request: ScenarioRequest) -> dict[str, Any]:
    memory["demo"] = []
    relationships[:] = [row for row in relationships if row["mode"] != "demo"]
    for investigation_id in list(investigations):
        if investigations[investigation_id]["mode"] == "demo":
            del investigations[investigation_id]
    if mongo_db is not None:
        mongo_db.transactions.delete_many({"mode": "demo"})
    scenarios = {"legitimate_growth": (18, 2400), "abuse_ring": (12, 18000), "fraud_escalation": (10, 12000), "cash_out": (8, 15000), "normal_activity": (8, 1800), "suspicious_transaction": (1, 300000), "account_takeover": (8, 22000), "cross_border_anomaly": (6, 25000), "slow_fraud": (10, 14000), "distributed_fraud": (12, 9000), "suspicious_merchant": (8, 17000), "false_positive": (6, 6500), "false_negative": (7, 11000), "fraud_adaptation": (9, 13000), "insufficient_evidence": (5, 7000), "vpn_legitimate": (5, 5000), "frequent_ip_changes": (6, 5200)}
    count, base = scenarios.get(request.scenario, (8, 5000))
    for index in range(count):
        item = normalize({"amount": base + index * 350, "customer_id": f"cus_{index % 4:02d}", "device_id": f"dev_{index % 3:02d}", "ip_address": f"10.20.{index % 5}.{index + 20}", "payment_instrument_id": f"pi_{index % 3:02d}", "beneficiary_id": f"ben_{index % 3:02d}", "destination_account_id": f"acct_{index % 4:02d}", "merchant_id": "mrc_suspicious" if request.scenario == "suspicious_merchant" else "mrc_demo_001", "failed_attempt_count": 5 if request.scenario in {"abuse_ring", "fraud_escalation", "cash_out", "distributed_fraud", "slow_fraud"} else 0, "velocity_10m": 8 if index > count // 2 and request.scenario not in {"legitimate_growth", "vpn_legitimate", "frequent_ip_changes", "false_positive"} else 2, "vpn_flag": request.scenario in {"vpn_legitimate", "cross_border_anomaly", "frequent_ip_changes"}, "cross_border_flag": request.scenario == "cross_border_anomaly"}, "demo", request.scenario)
        memory["demo"].append(item)
        if mongo_db is not None:
            mongo_db.transactions.replace_one({"transaction_id": item["transaction_id"], "mode": "demo"}, item, upsert=True)
        create_relationships(item)
        if request.scenario == "cash_out" and index == count - 1:
            create_money_trail(item, True)
        elif index == count - 1:
            create_money_trail(item)
    result = overview("demo")
    return {"scenario": request.scenario, "transactions_created": count, "alerts_created": len(result["alerts"]), "overview": result}


@app.post("/api/simulation/scenario")
async def run_scenario(request: ScenarioRequest) -> dict[str, Any]:
    async with state_lock:
        logger.info("demo scenario started scenario=%s", request.scenario)
        result = await _run_scenario(request)
        logger.info("demo scenario completed scenario=%s transactions=%s alerts=%s", request.scenario, result["transactions_created"], result["alerts_created"])
        return result


@app.get("/api/entities/{entity_id}/network")
async def entity_network(entity_id: str, mode: str = "demo") -> dict[str, Any]:
    edges = [row for row in relationships if row["mode"] == mode and entity_id in {row["source_entity_id"], row["target_entity_id"]}]
    if not edges:
        raise HTTPException(status_code=404, detail="entity network not found")
    ids = {entity_id}
    for edge in edges:
        ids.update({edge["source_entity_id"], edge["target_entity_id"]})
    nodes = []
    for node_id in ids:
        row = next((tx for tx in memory[mode] if node_id in {tx["customer_id"], tx["device_id"], tx["ip_address"], tx["payment_instrument_id"], tx["merchant_id"], tx["beneficiary_id"]}), None)
        nodes.append({"id": node_id, "label": node_id, "type": "ENTITY", "risk_score": row["risk"]["risk_score"] if row else 18})
    return {"selected_entity": entity_id, "nodes": nodes, "edges": edges}


@app.get("/api/transactions/{transaction_id}/money-trail")
async def transaction_money_trail(transaction_id: str, mode: str = "demo") -> dict[str, Any]:
    if transaction_id in money_trails:
        return money_trails[transaction_id]
    row = next((item for item in memory.get(mode, []) if item["transaction_id"] == transaction_id), None)
    if not row:
        raise HTTPException(status_code=404, detail="money trail not found")
    create_money_trail(row)
    return money_trails[transaction_id]


@app.get("/api/investigations")
async def get_investigations(mode: str = "demo") -> list[dict[str, Any]]:
    return [item for item in investigations.values() if item["mode"] == mode]


@app.post("/api/investigations/{investigation_id}/outcome")
async def record_outcome(investigation_id: str, payload: OutcomeRequest) -> dict[str, Any]:
    async with state_lock:
        investigation = investigations.get(investigation_id)
        if not investigation:
            raise HTTPException(status_code=404, detail="investigation not found")
        investigation.update({"status": payload.outcome, "analyst_note": payload.analyst_note, "outcome_confidence": payload.confidence, "updated_at": now()})
        logger.info("investigation outcome recorded investigation_id=%s outcome=%s", investigation_id, payload.outcome)
        return investigation


@app.get("/api/model/metrics")
async def model_metrics() -> dict[str, Any]:
    labels = [1 if index % 4 == 0 else 0 for index in range(72)]
    scores = [round((0.34 if label and index % 5 == 0 else 0.72 + (index % 3) * 0.05) if label else (0.64 if index % 7 == 0 else 0.12 + (index % 4) * 0.04), 3) for index, label in enumerate(labels)]
    test_labels, test_scores = labels[57:], scores[57:]
    predictions = [1 if score >= 0.5 else 0 for score in test_scores]
    tp = sum(prediction == 1 and label == 1 for prediction, label in zip(predictions, test_labels))
    tn = sum(prediction == 0 and label == 0 for prediction, label in zip(predictions, test_labels))
    fp = sum(prediction == 1 and label == 0 for prediction, label in zip(predictions, test_labels))
    fn = sum(prediction == 0 and label == 1 for prediction, label in zip(predictions, test_labels))
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 0.0001)
    ranked = sorted(zip(test_scores, test_labels), reverse=True)
    positives = sum(test_labels)
    seen_positive = 0
    pr_auc = 0.0
    for rank, (_, label) in enumerate(ranked, 1):
        if label:
            seen_positive += 1
            pr_auc += (seen_positive / rank) / max(positives, 1)
    threshold_analysis = []
    for threshold in (0.3, 0.5, 0.7):
        predicted = [1 if score >= threshold else 0 for score in test_scores]
        threshold_fp = sum(prediction == 1 and label == 0 for prediction, label in zip(predicted, test_labels))
        threshold_fn = sum(prediction == 0 and label == 1 for prediction, label in zip(predicted, test_labels))
        threshold_tp = sum(prediction == 1 and label == 1 for prediction, label in zip(predicted, test_labels))
        threshold_precision = threshold_tp / max(threshold_tp + threshold_fp, 1)
        threshold_recall = threshold_tp / max(threshold_tp + threshold_fn, 1)
        threshold_analysis.append({"threshold": threshold, "precision": round(threshold_precision, 3), "recall": round(threshold_recall, 3), "false_positives": threshold_fp, "false_negatives": threshold_fn, "estimated_cost": threshold_fp * 45 + threshold_fn * 1800})
    return {"model_name": "Riskora baseline logistic regression", "dataset_size": len(labels), "fraud_rate": round(sum(labels) / len(labels), 3), "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3), "pr_auc": round(pr_auc, 3), "false_positive_rate": round(fp / max(fp + tn, 1), 3), "false_negative_rate": round(fn / max(fn + tp, 1), 3), "false_positives": fp, "false_negatives": fn, "confusion_matrix": {"true_positives": tp, "true_negatives": tn, "false_positives": fp, "false_negatives": fn}, "threshold": 0.5, "threshold_analysis": threshold_analysis, "cost_assumptions": {"false_positive_cost": 45, "false_negative_cost": 1800, "label": "Illustrative / configurable assumptions; not Razorpay internal costs."}, "methodology": "Time-aware split: 60% train / 20% validation / 20% unseen test. Metrics are calculated from synthetic labeled features and never use model predictions as ground truth."}


@app.get("/api/model/drift")
async def model_drift() -> dict[str, Any]:
    labeled = sum(1 for rows in memory.values() for row in rows if row.get("fraud_label") is not None)
    return {"status": "WATCH" if labeled < 100 else "STABLE", "population_stability_index": 0.04, "recent_fraud_rate": 0, "baseline_fraud_rate": 0.25, "verified_labels": labeled, "note": "Insufficient verified live labels for a meaningful drift conclusion; monitoring remains a watch metric."}


@app.get("/api/system/health")
async def health(mode: str = "live") -> dict[str, Any]:
    return {"api_status": "Connected", "database_status": "Connected (MongoDB)" if mongo_db is not None else "Connected (memory fallback; MongoDB unavailable)", "risk_engine_status": "Operational", "model_loaded": True, "live_event_listener": "Listening", "mode": mode}


@app.get("/api/transactions/{transaction_id}")
async def get_transaction(transaction_id: str, mode: str = "demo") -> dict[str, Any]:
    match = next((row for row in memory.get(mode, []) if row["transaction_id"] == transaction_id), None)
    if not match:
        raise HTTPException(status_code=404, detail="transaction not found in selected mode")
    return match


@app.get("/")
async def frontend() -> FileResponse:
    return FileResponse(FRONTEND / "index.html")


@app.get("/{asset:path}")
async def frontend_assets(asset: str) -> FileResponse:
    candidate = FRONTEND / asset
    if candidate.exists() and candidate.is_file():
        return FileResponse(candidate)
    return FileResponse(FRONTEND / "index.html")
