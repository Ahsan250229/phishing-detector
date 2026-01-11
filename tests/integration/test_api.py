from fastapi.testclient import TestClient
from src.main import app

client = TestClient(app)


def _login(username: str, password: str) -> dict:
    resp = client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_health():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"


def test_scan_email_requires_auth():
    # Broken Access Control regression: protected endpoint should block anonymous calls
    resp = client.post("/api/scan-email", json={"email_text": "Hello there"})
    assert resp.status_code in (401, 403)


def test_scan_email_schema_with_auth():
    token_data = _login("admin", "Admin@12345")
    token = token_data["access_token"]

    resp = client.post(
        "/api/scan-email",
        headers={"Authorization": f"Bearer {token}"},
        json={"email_text": "Hello there"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "verdict" in data
    assert "score" in data
    assert "reasons" in data
    assert "urls" in data
    assert "request_id" in data
    assert "scan_id" in data
