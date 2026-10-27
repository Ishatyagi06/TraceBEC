"""Integration Tests for phisGuard FastAPI Endpoints."""

import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)
SAMPLES_DIR = Path(__file__).parent.parent.parent / "data" / "samples"


def test_health_and_root():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "healthy"}

    res_root = client.get("/")
    assert res_root.status_code == 200
    assert res_root.json()["status"] == "online"


def test_analyze_visible_text():
    payload = {
        "subject": "STRICTLY CONFIDENTIAL: Immediate Acquisition Wire",
        "body": "Treasury team, please wire $48,500 immediately to the escrow account coordinates. Do not discuss on the floor.",
        "sender": "Kenneth Lay, CEO <ceo.office@gmail.com>"
    }
    res = client.post("/api/v1/analyze/text", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "risk_assessment" in data
    assert data["risk_assessment"]["risk_category"] in ("HIGH", "REVIEW")
    assert len(data["risk_assessment"]["unavailable_evidence"]) > 0
    assert len(data["risk_assessment"]["safe_next_steps"]) > 0
    inv_id = data["id"]

    # Verify retrieval
    res_get = client.get(f"/api/v1/investigations/{inv_id}")
    assert res_get.status_code == 200
    assert res_get.json()["id"] == inv_id

    # Verify deletion
    res_del = client.delete(f"/api/v1/investigations/{inv_id}")
    assert res_del.status_code == 200
    assert res_del.json()["status"] == "deleted"


def test_analyze_eml_file_upload():
    eml_path = SAMPLES_DIR / "bec_ceo_wire_01.eml"
    assert eml_path.exists()

    with open(eml_path, "rb") as f:
        files = {"file": ("bec_ceo_wire_01.eml", f, "message/rfc822")}
        res = client.post("/api/v1/analyze/eml", files=files)

    assert res.status_code == 200
    data = res.json()
    assert data["source_type"] == "eml_upload"
    assert data["risk_assessment"]["risk_category"] == "HIGH"
    
    # Check observed signals
    signals = [s["title"] for s in data["risk_assessment"]["observed_evidence"]]
    assert "Reply-To Domain Mismatch" in signals
    assert "Display Name Spoofing with Free Webmail" in signals


def test_dataset_profile_endpoint():
    payload = {
        "records": [
            {"id": "1", "subject": "Wire Needed", "body": "Please wire funds today.", "label": 1},
            {"id": "2", "subject": "Meeting Notes", "body": "Notes from project review.", "label": 0}
        ]
    }
    res = client.post("/api/v1/datasets/profile", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["total_samples"] == 2
    assert "class_distribution" in data
    assert "leakage_audit" in data


def test_campaigns_graph_endpoint():
    res = client.get("/api/v1/campaigns/graph?campaign_id=camp_d5440b4df3ff")
    assert res.status_code == 200
    data = res.json()
    assert len(data["nodes"]) > 0
    assert len(data["edges"]) > 0
    assert data["metrics"]["email"] == 306
    assert data["metrics"]["campaign_candidate"] == 22
    assert data["selected_campaign"]["id"] == "camp_d5440b4df3ff"

