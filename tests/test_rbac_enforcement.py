from fastapi.testclient import TestClient
from src.main import app

client = TestClient(app)

def test_api_requires_auth():
    r = client.post("/api/scan-email", json={"email_text": "hi", "headers": {}, "attachments": []})
    assert r.status_code in (401, 403)

def test_admin_requires_admin_role():
    # no token -> must fail
    r = client.get("/admin/quarantine")
    assert r.status_code in (401, 403)
