import uuid
import pyotp
from fastapi.testclient import TestClient
from src.main import app

client = TestClient(app)

def register_user(username: str, password: str, role: str = "admin"):
    r = client.post("/auth/register", json={"username": username, "password": password, "role": role})
    assert r.status_code == 200, r.text

def login(username: str, password: str) -> str:
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]

def otp_setup(token: str) -> str:
    r = client.post("/auth/otp/setup", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    return r.json()["otp_secret"]

def otp_verify(token: str, otp_code: str) -> str:
    r = client.post(
        "/auth/otp/verify",
        headers={"Authorization": f"Bearer {token}"},
        json={"otp_code": otp_code},
    )
    assert r.status_code == 200, r.text
    return r.json()["access_token"]

def test_admin_endpoint_requires_otp_after_enabling_otp():
    u = f"admin-{uuid.uuid4().hex[:8]}"
    p = "Admin@12345!"
    register_user(u, p, role="admin")

    token = login(u, p)
    secret = otp_setup(token)

    # After OTP is enabled, old token must be blocked from admin endpoints
    r = client.get("/admin/quarantine", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    assert r.json()["detail"] in ("OTP verification required", "2FA verification required")

    # Verify OTP -> get a new token
    totp = pyotp.TOTP(secret)
    new_token = otp_verify(token, totp.now())

    # Now admin endpoint should work (even if quarantine list is empty)
    r2 = client.get("/admin/quarantine", headers={"Authorization": f"Bearer {new_token}"})
    assert r2.status_code == 200, r2.text

def test_invalid_otp_rejected():
    u = f"admin-{uuid.uuid4().hex[:8]}"
    p = "Admin@12345!"
    register_user(u, p, role="admin")

    token = login(u, p)
    _secret = otp_setup(token)

    # Wrong OTP code must fail
    r = client.post(
        "/auth/otp/verify",
        headers={"Authorization": f"Bearer {token}"},
        json={"otp_code": "000000"},
    )
    assert r.status_code in (400, 401, 403), r.text
