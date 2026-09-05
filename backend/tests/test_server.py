import pytest
from fastapi.testclient import TestClient

from backend.server import investigations, memory, money_trails, relationships, app

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_state():
    memory["live"].clear()
    memory["demo"].clear()
    relationships.clear()
    money_trails.clear()
    investigations.clear()
    yield


def test_live_zero_state_and_duplicate_protection():
    response = client.get("/api/overview?mode=live")
    assert response.status_code == 200
    assert response.json()["total_transactions"] == 0

    payload = {"transaction_id": "txn_test_001", "amount": 2500, "customer_id": "cus_test_001"}
    assert client.post("/api/transactions", json=payload).status_code == 201
    assert client.post("/api/transactions", json=payload).status_code == 409


def test_demo_graph_money_trail_and_outcome():
    scenario = client.post("/api/simulation/scenario", json={"scenario": "cash_out"})
    assert scenario.status_code == 200
    data = scenario.json()
    assert data["transactions_created"] == 8
    alert = data["overview"]["alerts"][0]

    network = client.get(f"/api/entities/{alert['entity']}/network?mode=demo")
    assert network.status_code == 200
    assert len(network.json()["nodes"]) >= 3
    assert len(network.json()["edges"]) >= 3

    trail = client.get(f"/api/transactions/{alert['transaction_id']}/money-trail?mode=demo")
    assert trail.status_code == 200
    assert trail.json()["cash_out_detected"] is True
    assert "CASH-OUT DETECTED" in trail.json()["notice"]

    outcome = client.post(f"/api/investigations/{alert['investigation_id']}/outcome", json={"outcome": "UNCERTAIN", "confidence": 92, "analyst_note": "Verified review"})
    assert outcome.status_code == 200
    assert outcome.json()["status"] == "UNCERTAIN"


def test_validation_and_model_contracts():
    assert client.post("/api/simulation/scenario", json={"scenario": "not-a-scenario"}).status_code == 422
    assert client.post("/api/transactions", json={"amount": 0}).status_code == 422

    metrics = client.get("/api/model/metrics")
    assert metrics.status_code == 200
    assert metrics.json()["dataset_size"] > 0
    assert "confusion_matrix" in metrics.json()

    drift = client.get("/api/model/drift")
    assert drift.status_code == 200
    assert drift.json()["status"] == "WATCH"
