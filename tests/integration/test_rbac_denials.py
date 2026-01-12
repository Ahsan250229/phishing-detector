import uuid
from fastapi.testclient import TestClient
from src.main import app

client = TestClient(app)

def register_user(username: str, password: str, role: str = "analyst"):
    r = client.post("/auth/register", json={"username": username, "password": password, "role": role})
    assert r.status_code == 200, r.text

def login(username: str, password: str) -> str:
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]

def test_non_admin_denied_admin_ping():
    u = f"user-{uuid.uuid4().hex[:8]}"
    p = "User@12345!"
    register_user(u, p, role="analyst")
    token = login(u, p)

    r = client.get("/auth/admin/ping", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    assert r.json()["detail"] in ("Insufficient role", "Admin privileges required")

def test_non_admin_denied_admin_quarantine_list():
    u = f"user-{uuid.uuid4().hex[:8]}"
    p = "User@12345!"
    register_user(u, p, role="analyst")
    token = login(u, p)

    r = client.get("/admin/quarantine", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    assert r.json()["detail"] in ("Insufficient role", "Admin privileges required")
