# Threat Model – Phishing Email Detector

## Assets
- User credentials
- OTP secrets
- Email analysis reports
- Quarantined emails

## Entry Points
- Login endpoint
- Email upload/paste
- Report export
- Admin dashboard

## Threats and Mitigations

| Threat | Description | Mitigation |
|------|------------|------------|
| Brute force login | Attackers attempt repeated logins | Rate limiting, logging |
| Privilege escalation | Analyst accesses admin features | RBAC enforcement |
| Malicious email HTML | XSS via email content | HTML sanitization |
| Data leakage | Unauthorized report access | Access control, auditing |

## Risk Assessment
Most threats are mitigated through authentication, authorization, secure coding, and monitoring.

## Detailed Risk Assessment and Control Mapping

The following table evaluates identified threats based on likelihood and impact, assigns an overall risk rating, and maps each risk to implemented security controls.

| Threat | Likelihood | Impact | Risk Rating | Security Controls |
|------|------------|--------|-------------|-------------------|
| Brute force login | Medium | High | High | Rate limiting, account lockout, logging, 2FA |
| Privilege escalation | Low | High | Medium | RBAC enforcement, role validation, audit logs |
| Malicious email HTML (XSS) | Medium | Medium | Medium | HTML sanitization, input validation, output encoding |
| Data leakage | Low | High | Medium | Access control, encryption at rest, auditing |
