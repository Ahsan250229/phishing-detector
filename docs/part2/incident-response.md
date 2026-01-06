# Part 2 — Incident Response Runbook

## 1. Purpose
Define actions for detecting, containing, and recovering from security incidents affecting the phishing detector prototype.

## 2. Severity Levels
- SEV1: Active compromise, data exposure, credential leakage, or service unusable.
- SEV2: High-risk vulnerability found, partial outage, repeated abuse attempts.
- SEV3: Minor vulnerability, low impact bug, single abnormal event.

## 3. Detection Sources
- CI failures (tests/security/SAST/audit)
- Dependabot alerts (critical/high)
- Error spikes in logs
- User-reported vulnerability (SECURITY.md reporting path)

## 4. Response Steps (Standard)
### 4.1 Containment
- Disable affected endpoint if necessary.
- Remove exposed secrets (rotate keys; invalidate tokens).
- Block abusive IPs (documented measure; optional implementation).

### 4.2 Eradication
- Patch vulnerable code or dependency.
- Add regression tests that reproduce the issue.
- Re-run CI and security workflows to confirm fix.

### 4.3 Recovery
- Deploy patched version (prototype deployment).
- Monitor logs for recurrence.
- Confirm normal service health.

## 5. Communication Plan (Academic project)
- Notify team members immediately in group channel.
- Record incident summary in docs/part2/incident-log.md (optional).
- Inform teaching staff if incident affects assessment demonstration or data handling.

## 6. Post-Incident Review (PIR)
Capture:
- What happened (timeline)
- Root cause
- Fix applied
- Preventative actions (tests, controls, documentation updates)
- Lessons learned
