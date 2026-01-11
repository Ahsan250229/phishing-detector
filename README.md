# Phishing Email Detector (DevSecOps Project)

## Overview
This project is a **phishing email detection prototype** developed using **DevSecOps principles**.  
Security is integrated throughout the software lifecycle, including **design, development, testing, CI/CD planning, monitoring, and incident response**.

The system analyses email content using **rule-based heuristics** to identify potential phishing indicators and returns a structured risk assessment.

---

## Features (Implemented)
- Rule-based phishing detection using heuristic analysis
- Risk-based verdicts: **SAFE / SUSPICIOUS / PHISHING**
- URL extraction and analysis
- Header and attachment analysis
- Explainable scoring with detection reasons
- Email quarantine and report generation (CSV / PDF)
- JWT-based authentication
- Secure input validation and error handling
- Structured logging with request identifiers

---

## Planned / Future Enhancements
- Machine-learning-based phishing classification
- CI/CD pipeline automation using GitHub Actions
- Static Application Security Testing (SAST)
- Dynamic Application Security Testing (DAST) using OWASP ZAP
- Production-grade deployment and scaling

---

## Technology Stack
- **Backend Framework:** FastAPI
- **ASGI Server:** Uvicorn
- **Authentication:** JWT, RBAC, TOTP (2FA)
- **Security Libraries:** python-jose, passlib, pyotp
- **Testing:** Pytest (unit, integration, security regression)
- **Security Testing:** Input validation, access control enforcement
- **CI/CD (Design):** GitHub Actions
- **Planned Security Tools:** Bandit, Semgrep, pip-audit, OWASP ZAP

---

## Repository Structure
```
src/       - Application source code
tests/     - Unit, integration, and security tests
docs/      - Project documentation
ci-cd/     - CI/CD pipeline documentation
.github/   - GitHub Actions workflows
```

## Running the Application

### Local Setup

```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn src.main:app --reload
```

### Access Points
- API Base URL: http://127.0.0.1:8000
- Swagger UI: http://127.0.0.1:8000/docs
- ReDoc: http://127.0.0.1:8000/redoc

## Running Tests
```bash
pytest -q
```
