# Part 2 — Logging and Monitoring Plan

## 1. Logging Objectives
- Provide traceability for scans and decisions.
- Support incident triage and debugging.
- Avoid logging sensitive information.

## 2. What to Log (Structured Fields)
Minimum fields per request:
- timestamp
- request_id (unique per request)
- endpoint
- verdict (SAFE/SUSPICIOUS/PHISHING)
- score
- triggered_rules (list)
- extracted_url_count
- latency_ms
- status_code

## 3. What NOT to Log
- Raw credentials (passwords, OTPs)
- Tokens, secrets, API keys
- Full raw email content (store only safe excerpts if required)

## 4. Monitoring Signals (Prototype-level)
Minimum metrics/signals:
- Error rate (4xx/5xx)
- High latency (slow scans)
- Spike in requests (possible abuse)
- Spike in PHISHING verdicts (possible campaign)

## 5. Alerting (Documented Plan)
Alerts should trigger on:
- Sustained 5xx errors
- Sudden request spikes (rate-based threshold)
- CI pipeline failures (build breaks)
- Dependency critical vulnerability alerts (Dependabot)

## 6. Evidence
- Log output is visible in local run (stdout or file).
- Documented fields + policy in this file.
- Link to incident response runbook for escalation steps.
