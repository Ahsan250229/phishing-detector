from fastapi.testclient import TestClient
from src.main import app

client = TestClient(app)

def test_health():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"

def test_scan_email_schema():
    resp = client.post("/api/scan-email", json={"email_text": "Hello there"})
    assert resp.status_code == 200
    data = resp.json()
    assert "verdict" in data
    assert "score" in data
    assert "reasons" in data
    assert "urls" in data
    assert "request_id" in data
