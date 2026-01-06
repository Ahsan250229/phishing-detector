# Phishing Email Detector (DevSecOps Project)

## Overview
This project is a **phishing email detection prototype** developed using **DevSecOps principles**.  
Security is integrated throughout the software lifecycle, including **design, development, testing, CI/CD planning, monitoring, and incident response**.

The system analyses email content using **rule-based heuristics** to identify potential phishing indicators and returns a structured risk assessment.

---

## Features (Implemented)
- Rule-based phishing email detection using heuristics
- Risk-based verdicts: **SAFE / SUSPICIOUS / PHISHING**
- URL extraction and analysis
- Scoring-based decision logic with explainable reasons
- Secure input validation and error handling
- Structured logging with unique request identifiers

---

## Planned / Future Enhancements
- Authentication and role-based access control (RBAC)
- Two-factor authentication (2FA)
- Email quarantine and reporting workflows
- Machine-learning-based phishing classification
- CI/CD pipeline automation using GitHub Actions
- Static Application Security Testing (SAST)
- Dynamic Application Security Testing (DAST) using OWASP ZAP
- Production-grade deployment and scaling

---

## Technology Stack
- **Python (Flask)**
- **Pytest** (unit and integration testing)
- **GitHub Actions** (planned CI/CD)
- **Bandit / Semgrep** (planned SAST)
- **pip-audit** (dependency vulnerability scanning)
- **OWASP ZAP** (planned DAST)

---

## Repository Structure
```
src/       - Application source code
tests/     - Unit, integration, and security tests
docs/      - Project documentation
ci-cd/     - CI/CD pipeline documentation
.github/   - GitHub Actions workflows
```

## Run (Python / Flask)

### Local Setup

```bash
pip install -r requirements.txt
python -m flask run
pytest -q
```
