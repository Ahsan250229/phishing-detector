# Part 2 — Security Testing Strategy (DevSecOps)

## 1. Objectives
- Detect insecure code patterns early (SAST).
- Identify vulnerable dependencies (dependency audit + Dependabot).
- Validate input handling, error handling, and logging controls.
- Provide repeatable evidence via GitHub Actions.

## 2. Automated Security Controls
### 2.1 Dependency Vulnerability Monitoring
- Dependabot alerts: enabled in GitHub Security settings.
- Additional automated checks in CI:
  - Python: pip-audit (if requirements.txt exists)
  - Node: npm audit (if package.json exists)
  - PHP: composer audit (if composer.json exists)

### 2.2 SAST (Static Application Security Testing)
- Semgrep scan runs in GitHub Actions on push/PR.
- Baseline config: semgrep --config=auto
- Findings are reviewed and either fixed or documented with justification.

## 3. Manual Security Checks (Minimum)
- Validate server-side input validation rules:
  - Maximum request size
  - Required fields present
  - Safe parsing of email text / HTML
- Verify error responses:
  - No internal stack traces shown to users
  - Consistent error format
- Verify logging:
  - Request IDs exist
  - No secrets/credentials logged
  - Logs contain verdict + rule triggers only (sanitized)

## 4. Mapped to Threat Model
This security testing strategy supports threat model mitigations:
- Injection / malformed input → validation + negative tests
- Dependency vulnerabilities → Dependabot + audit workflow
- Insecure coding patterns → Semgrep SAST
- Incident response readiness → runbook and monitoring plan

## 5. Security Evidence for Assessment
- GitHub Actions runs for:
  - CI tests
  - Dependency audit
  - SAST (Semgrep)
- Security settings screenshot evidence:
  - Dependabot enabled
  - Security policy enabled
