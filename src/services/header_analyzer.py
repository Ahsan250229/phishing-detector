# src/services/header_analyzer.py
from __future__ import annotations

import re
from typing import Dict, List, Tuple, Optional


_FROM_RE = re.compile(r"^From:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_REPLYTO_RE = re.compile(r"^Reply-To:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_AUTHRES_RE = re.compile(r"^Authentication-Results:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_RECEIVED_RE = re.compile(r"^Received:\s*(.+)$", re.IGNORECASE | re.MULTILINE)

_EMAIL_RE = re.compile(r"([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"@([A-Z0-9.-]+\.[A-Z]{2,})", re.IGNORECASE)

# Very simple “brand impersonation” cues for demo-grade evidence
_IMPERSONATION_WORDS = [
    "microsoft", "office365", "google", "gmail", "outlook", "bank", "paypal", "apple", "it support",
]


def _extract_first(pattern: re.Pattern, text: str) -> Optional[str]:
    m = pattern.search(text or "")
    return m.group(1).strip() if m else None


def _extract_email(value: str) -> Optional[str]:
    if not value:
        return None
    m = _EMAIL_RE.search(value)
    return m.group(1).lower() if m else None


def _domain(email: Optional[str]) -> Optional[str]:
    if not email:
        return None
    m = _DOMAIN_RE.search(email)
    return m.group(1).lower() if m else None


def analyze_headers(headers_text: str) -> Tuple[int, List[str], Dict[str, object]]:
    """
    Demo-grade header spoof analysis.
    Returns: (score, findings, details)
    - score: integer points
    - findings: human-readable indicators
    - details: parsed fields that can be stored in quarantine/report
    """
    headers_text = headers_text or ""
    findings: List[str] = []
    score = 0

    from_line = _extract_first(_FROM_RE, headers_text)
    reply_to_line = _extract_first(_REPLYTO_RE, headers_text)
    auth_results = _extract_first(_AUTHRES_RE, headers_text)
    received_count = len(_RECEIVED_RE.findall(headers_text))

    from_email = _extract_email(from_line or "")
    reply_to_email = _extract_email(reply_to_line or "")
    from_domain = _domain(from_email)
    reply_to_domain = _domain(reply_to_email)

    # 1) From vs Reply-To mismatch (common phishing pattern)
    if from_email and reply_to_email and from_email != reply_to_email:
        findings.append("From and Reply-To addresses do not match (possible spoofing)")
        score += 20

    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        findings.append("From and Reply-To domains do not match (possible spoofing)")
        score += 10

    # 2) Missing Received chain (very weak signal but useful evidence)
    if received_count == 0:
        findings.append("No Received headers found (suspicious or incomplete header set)")
        score += 10

    # 3) Parse SPF/DKIM/DMARC outcomes if Authentication-Results exists
    if auth_results:
        ar = auth_results.lower()
        # crude token checks (works for most typical Authentication-Results formats)
        if "spf=fail" in ar or "spf=softfail" in ar:
            findings.append("SPF indicates fail/softfail")
            score += 20
        if "dkim=fail" in ar:
            findings.append("DKIM indicates fail")
            score += 20
        if "dmarc=fail" in ar:
            findings.append("DMARC indicates fail")
            score += 20
    else:
        findings.append("Authentication-Results header not present (cannot verify SPF/DKIM/DMARC)")
        score += 5

    # 4) Display-name/brand impersonation cues (demo-grade)
    # Use the raw From: line (may contain display name)
    from_line_l = (from_line or "").lower()
    for w in _IMPERSONATION_WORDS:
        if w in from_line_l:
            findings.append(f"Potential impersonation keyword in From header: '{w}'")
            score += 10
            break

    details: Dict[str, object] = {
        "from": from_line,
        "reply_to": reply_to_line,
        "from_email": from_email,
        "reply_to_email": reply_to_email,
        "authentication_results": auth_results,
        "received_count": received_count,
    }

    return score, findings, details
