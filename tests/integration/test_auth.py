import uuid
import time
import pyotp
from fastapi.testclient import TestClient
from src.main import app

client = TestClient(app)


def _register(username: str, password: str, role: str = "analyst") -> None:
    resp = client.post(
        "/auth/register",
        json={"username": username, "password": password, "role": role},
    )
    assert resp.status_code == 200, resp.text


def _login(username: str, password: str) -> dict:
    resp = client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_login_success_and_invalid_password():
    ok = _login("admin", "Admin@12345")
    assert "access_token" in ok
    assert "requires_otp" in ok

    bad = client.post(
        "/auth/login",
        json={"username": "admin", "password": "WrongPassword123"},
    )
    assert bad.status_code == 401
    assert bad.json()["detail"] == "Invalid credentials"


def test_otp_flow_enforced_on_protected_api():
    username = f"otp_user_{uuid.uuid4().hex[:8]}"
    password = "Test@12345"
    _register(username, password, role="analyst")

    login_data = _login(username, password)
    token = login_data["access_token"]

    # OTP not enabled yet → scan should succeed
    r1 = client.post(
        "/api/scan-email",
        headers={"Authorization": f"Bearer {token}"},
        json={"email_text": "hello"},
    )
    assert r1.status_code == 200, r1.text

    # Enable OTP
    setup = client.post(
        "/auth/otp/setup",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert setup.status_code == 200, setup.text
    secret = setup.json()["otp_secret"]

    # Old token should now be blocked
    r2 = client.post(
        "/api/scan-email",
        headers={"Authorization": f"Bearer {token}"},
        json={"email_text": "hello again"},
    )
    assert r2.status_code == 403
    assert r2.json()["detail"] == "OTP verification required"

    # Verify OTP (retry-safe)
    totp = pyotp.TOTP(secret)
    verified = client.post(
        "/auth/otp/verify",
        headers={"Authorization": f"Bearer {token}"},
        json={"otp_code": totp.now()},
    )

    if verified.status_code != 200:
        time.sleep(1)
        verified = client.post(
            "/auth/otp/verify",
            headers={"Authorization": f"Bearer {token}"},
            json={"otp_code": totp.now()},
        )

    assert verified.status_code == 200, verified.text
    upgraded_token = verified.json()["access_token"]

    # Scan succeeds again
    r3 = client.post(
        "/api/scan-email",
        headers={"Authorization": f"Bearer {upgraded_token}"},
        json={"email_text": "final hello"},
    )
    assert r3.status_code == 200, r3.text


def test_rbac_admin_only_exports():
    # Create scan as admin
    admin = _login("admin", "Admin@12345")
    admin_token = admin["access_token"]

    scan = client.post(
        "/api/scan-email",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"email_text": "scan for report"},
    )
    assert scan.status_code == 200, scan.text
    scan_id = scan.json()["scan_id"]

    # Create analyst
    username = f"analyst_{uuid.uuid4().hex[:8]}"
    password = "Test@12345"
    _register(username, password, role="analyst")
    analyst_token = _login(username, password)["access_token"]

    # Analyst blocked
    pdf_analyst = client.get(
        f"/api/reports/{scan_id}.pdf",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert pdf_analyst.status_code == 403
    assert pdf_analyst.json()["detail"] == "Insufficient role"

    csv_analyst = client.get(
        f"/api/reports/{scan_id}.csv",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert csv_analyst.status_code == 403
    assert csv_analyst.json()["detail"] == "Insufficient role"

    # Admin allowed
    pdf_admin = client.get(
        f"/api/reports/{scan_id}.pdf",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert pdf_admin.status_code == 200
    assert pdf_admin.headers["content-type"].startswith("application/pdf")

    csv_admin = client.get(
        f"/api/reports/{scan_id}.csv",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert csv_admin.status_code == 200
    assert csv_admin.headers["content-type"].startswith("text/csv")
