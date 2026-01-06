# Part 2 — Implementation Plan (DevSecOps)

## 1. Purpose
This document defines the implementation approach for the Phishing Email Detector prototype and maps features to secure DevSecOps practices (build, test, security checks, monitoring, and incident response).

## 2. Scope (Part 2)
### In scope
- Working prototype: API that accepts email text and returns phishing verdict + reasons.
- Secure input handling, logging, and basic monitoring signals.
- Automated tests (unit + integration) and CI pipeline.
- Security automation: dependency vulnerability checks + SAST scanning.
- Incident response runbook (documented).

### Out of scope (for prototype stage)
- Large-scale production deployment.
- Advanced ML training pipeline (optional future enhancement).
- Full SIEM integration.

## 3. Target System Features
### 3.1 API Endpoints (minimum)
- GET /api/health
  - Returns status and version metadata.
- POST /api/scan-email
  - Input: email content (plain text or JSON payload)
  - Output: verdict, score, reasons, extracted URLs, request_id

### 3.2 Detection Engine (rule-based v1)
Rules produce a score and “reasons”. Minimum rules:
- Presence of suspicious keywords (urgent/verify/password).
- Extracted URLs with suspicious patterns (IP address domains, punycode, very long domains).
- Excessive links / shortened URLs.
- Requests for credentials or financial information.

Output format example:
{
  "verdict": "PHISHING",
  "score": 82,
  "reasons": ["Urgent language", "Suspicious domain", "Credential request"],
  "urls": ["http://example..."],
  "request_id": "..."
}

## 4. Planned Repo Structure (Part 2)
- src/
  - core/ (detection rules + scoring)
  - api/ (routes/controllers)
  - services/ (parsing, URL extraction, utilities)
  - config/ (non-secret config)
- tests/
  - unit/
  - integration/
  - security/
- docs/part2/ (Part 2 deliverable docs)
- .github/workflows/ (CI + security automation)
- docker/ (optional containerization)

## 5. Secure Coding Standards
- Validate all input (type, size, required fields).
- Reject oversized requests to reduce DoS risk.
- Never log secrets or raw credentials (sanitize before logging).
- Consistent error handling; do not leak stack traces to users.
- Keep secrets out of Git: use .env locally and commit only .env.example.

## 6. Implementation Milestones
### Milestone 1 — Skeleton (Week 7)
- Create src structure + /api/health endpoint.
- Implement scan-email endpoint returning stub response.
- Update README with run steps.

### Milestone 2 — Detection engine v1 (Week 7–8)
- Implement URL extraction + rule scoring.
- Return verdict + reasons.

### Milestone 3 — Testing (Week 8)
- Unit tests for rules and scoring.
- Integration test for scan endpoint.

### Milestone 4 — DevSecOps Automation (Week 8–9)
- CI runs on push/PR.
- Dependency audit workflow.
- SAST workflow (Semgrep).

### Milestone 5 — Logging/Monitoring + Incident Response (Week 9–10)
- Structured logs with request_id and verdict.
- Monitoring plan documented.
- Incident response runbook documented.

## 7. Definition of Done (Part 2)
- Prototype runs and returns realistic verdicts for sample emails.
- CI green (tests pass).
- Dependency checks and SAST run in GitHub Actions.
- Logs exist and are documented.
- Incident response plan exists and is aligned with threat model.
