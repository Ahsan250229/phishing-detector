from fastapi.testclient import TestClient
from src.main import app

client = TestClient(app)


def _login_admin() -> str:
    resp = client.post("/auth/login", json={"username": "admin", "password": "Admin@12345"})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def test_security_header_nosniff_present():
    # OWASP: Security Misconfiguration regression check
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"


def test_dos_prevention_email_too_large_returns_rejected():
    # OWASP: DoS / resource exhaustion regression check
    token = _login_admin()
    huge = "A" * 30000  # > default MAX_EMAIL_CHARS=20000

    resp = client.post(
        "/api/scan-email",
        headers={"Authorization": f"Bearer {token}"},
        json={"email_text": huge},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["verdict"] == "REJECTED"
    assert data["score"] == 0


def test_internal_error_does_not_leak_stacktrace(monkeypatch):
    # OWASP: Security Logging & Monitoring / Info Disclosure regression check
    # Force an exception inside scan route via monkeypatch, then ensure generic 500 response.
    token = _login_admin()

    from src.core import detector

    def boom(_text: str):
        raise RuntimeError("Sensitive stacktrace detail should not be exposed")

    monkeypatch.setattr(detector, "analyze_email", boom)

    resp = client.post(
        "/api/scan-email",
        headers={"Authorization": f"Bearer {token}"},
        json={"email_text": "trigger error"},
    )

    assert resp.status_code == 500
    body = resp.json()
    assert body.get("error") == "Internal Server Error"
    assert "Sensitive stacktrace detail" not in resp.text
