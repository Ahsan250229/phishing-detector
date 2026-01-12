from fastapi.testclient import TestClient
from src.main import app

client = TestClient(app)

def test_missing_auth_header_denied():
    r = client.post("/api/scan-email", json={"email_text": "hello"})
    assert r.status_code in (401, 403)

def test_malformed_token_denied():
    r = client.post(
        "/api/scan-email",
        headers={"Authorization": "Bearer not-a-real-token"},
        json={"email_text": "hello"},
    )
    assert r.status_code == 401
    assert r.json()["detail"] in ("Invalid or expired token", "Invalid token payload")

def test_wrong_scheme_denied():
    r = client.post(
        "/api/scan-email",
        headers={"Authorization": "Token abc.def.ghi"},
        json={"email_text": "hello"},
    )
    assert r.status_code in (401, 403)
