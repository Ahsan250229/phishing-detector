# Part 2 — Testing Plan

## 1. Testing Objectives
- Verify detection logic correctness and stability.
- Ensure API returns consistent, valid JSON with expected fields.
- Confirm secure input handling and predictable failures.
- Provide automated evidence via CI/CD.

## 2. Test Types and Coverage
### 2.1 Unit Tests (tests/unit)
Focus: detection rules, scoring, URL extraction.
Minimum unit tests:
- Rule triggers correctly for known phishing phrases.
- URL extraction returns expected URLs for sample text.
- Score calculation is deterministic.
- Verdict thresholds map to scores.

### 2.2 Integration Tests (tests/integration)
Focus: API endpoint behavior end-to-end.
Minimum integration tests:
- GET /api/health returns HTTP 200.
- POST /api/scan-email returns HTTP 200 for valid payload.
- Response schema includes: verdict, score, reasons, urls, request_id.

### 2.3 Security Tests (tests/security)
Focus: negative tests + basic abuse cases.
Minimum security tests:
- Oversized input is rejected (413 or 400).
- Non-JSON content type is rejected where applicable.
- Injection-like payloads are safely handled (no stack trace, no crash).
- Logs do not contain raw sensitive content.

## 3. Test Data
- Include sample benign emails and phishing-like emails in:
  - tests/fixtures/ (recommended)
- Data should be synthetic (no real credentials).

## 4. Acceptance Criteria
- CI runs unit tests on every push/PR.
- All tests pass in CI (green build).
- At least:
  - 8–15 unit tests (rules + scoring)
  - 2–4 integration tests
  - 3–5 security tests

## 5. How Tests Run (by stack)
### Python (pytest)
- Install: pip install -r requirements.txt
- Run: pytest -q

### Node.js (npm)
- Install: npm ci
- Run: npm test

### PHP (phpunit)
- Install: composer install
- Run: ./vendor/bin/phpunit

## 6. Reporting Evidence
- GitHub Actions logs serve as the primary evidence.
- Any failed run will be documented with the root cause and fix in commit history.
