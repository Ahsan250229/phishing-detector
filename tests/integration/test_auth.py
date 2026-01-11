import pyotp
from fastapi.testclient import TestClient
from src.main import app

client = TestClient(app)


def _register(username: str, password: str, role: str = "analyst") -> None:
    resp = client.post("/auth/register", json={"username": username, "password": password, "role": role})
    # register can fail if already exists in repeated local runs; allow both outcomes
    assert resp.status_code in (200, 400), resp.text


def _login(username: str, password: str) -> dict:
    resp = client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_login_success_and_invalid_password():
    ok = _login("admin", "Admin@12345")
    assert "access_token" in ok
    assert "requires_otp" in ok

    bad = client.post("/auth/login", json={"username": "admin", "password": "WrongPassword123"})
    assert bad.status_code == 401
    assert bad.json()["detail"] == "Invalid credentials"


def test_otp_flow_enforced_on_protected_api():
    # 1) create user
    username = "otp_user"
    password = "Test@12345"
    _register(username, password, role="analyst")

    # 2) login (otp not enabled yet)
    login_data = _login(username, password)
    token = login_data["access_token"]

    # scan should work because otp_enabled=False
    resp1 = client.post(
        "/api/scan-email",
        headers={"Authorization": f"Bearer {token}"},
        json={"email_text": "hello"},
    )
    assert resp1.status_code == 200, resp1.text

    # 3) enable OTP
    setup = client.post("/auth/otp/setup", headers={"Authorization": f"Bearer {token}"})
    assert setup.status_code == 200, setup.text
    secret = setup.json()["otp_secret"]

    # 4) after enabling otp, old token has otp_verified=False, so protected route must fail
    resp2 = client.post(
        "/api/scan-email",
        headers={"Authorization": f"Bearer {token}"},
        json={"email_text": "hello again"},
    )
    assert resp2.status_code == 403
    assert resp2.json()["detail"] == "OTP verification required"

    # 5) verify OTP to get upgraded token (otp_verified=True)
    code = pyotp.TOTP(secret).now()
    verified = client.post(
        "/auth/otp/verify",
        headers={"Authorization": f"Bearer {token}"},
        json={"otp_code": code},
    )
    assert verified.status_code == 200, verified.text
    upgraded_token = verified.json()["access_token"]

    # 6) protected route should now succeed
    resp3 = client.post(
        "/api/scan-email",
        headers={"Authorization": f"Bearer {upgraded_token}"},
        json={"email_text": "final hello"},
    )
    assert resp3.status_code == 200, resp3.text


def test_rbac_admin_only_exports():
    # Create a scan as admin
    admin_login = _login("admin", "Admin@12345")
    admin_token = admin_login["access_token"]

    scan = client.post(
        "/api/scan-email",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"email_text": "scan for report"},
    )
    assert scan.status_code == 200, scan.text
    scan_id = scan.json()["scan_id"]

    # Create analyst user
    username = "analyst_user"
    password = "Test@12345"
    _register(username, password, role="analyst")
    analyst_login = _login(username, password)
    analyst_token = analyst_login["access_token"]

    # Analyst must be blocked from exports (RBAC)
    pdf_as_analyst = client.get(
        f"/api/reports/{scan_id}.pdf",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert pdf_as_analyst.status_code == 403

    csv_as_analyst = client.get(
        f"/api/reports/{scan_id}.csv",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert csv_as_analyst.status_code == 403

    # Admin should be allowed
    pdf_as_admin = client.get(
        f"/api/reports/{scan_id}.pdf",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert pdf_as_admin.status_code == 200
    assert pdf_as_admin.headers["content-type"].startswith("application/pdf")

    csv_as_admin = client.get(
        f"/api/reports/{scan_id}.csv",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert csv_as_admin.status_code == 200
    assert csv_as_admin.headers["content-type"].startswith("text/csv")
