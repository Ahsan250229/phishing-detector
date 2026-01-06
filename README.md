# Phishing Email Detector (DevSecOps Project)

## Overview
This project is a **phishing email detection prototype** developed using **DevSecOps principles**.  
Security is integrated throughout the software lifecycle, including **design, development, testing, CI/CD automation, monitoring, and incident response**.

The system analyses email content using **rule-based heuristics** to identify potential phishing indicators and returns a structured risk assessment.

---

## Features (Implemented)
- Rule-based phishing email detection using heuristics
- Risk-based verdicts: **SAFE / SUSPICIOUS / PHISHING**
- URL extraction and analysis
- Scoring-based decision logic with explainable reasons
- Secure input validation and error handling
- Structured logging with unique request identifiers
- Automated CI/CD using GitHub Actions
- Dependency vulnerability monitoring via Dependabot
- Static Application Security Testing (SAST) using open-source tools

---

## Planned / Future Enhancements
- Authentication and role-based access control (RBAC)
- Two-factor authentication (2FA)
- Email quarantine and reporting workflows
- Machine-learning-based phishing classification
- Dynamic Application Security Testing (DAST) using OWASP ZAP
- Production-grade deployment and scaling

---

## Technology Stack
- **Python (FastAPI)**
- **Pydantic** (data validation)
- **Pytest** (unit and integration testing)
- **GitHub Actions** (CI/CD automation)
- **Semgrep** (SAST)
- **pip-audit** (dependency vulnerability scanning)
- **OWASP ZAP** (planned DAST)

---


## Repository Structure
'''
src/       - Application source code
tests/     - Unit, integration, and security tests
docs/      - Project documentation (Part 1 & Part 2)
ci-cd/     - CI/CD pipeline documentation
.github/   - GitHub Actions workflows
'''


---

## Run (Python / FastAPI)

### Local Setup
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
uvicorn src.main:app --reload

pytest -q


---

# Step-by-step: how to apply this on GitHub
1. Open your repository → `README.md`
2. Click the **pencil icon** (Edit)
3. Find the section that starts at **“Repository Structure”**
4. Replace that whole section with the block above
5. Click **Preview** tab to confirm it looks clean
6. **Commit changes**

✅ Commit message:

