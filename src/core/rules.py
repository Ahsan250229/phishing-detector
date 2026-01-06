import re
from typing import List, Tuple

SUSPICIOUS_KEYWORDS = [
    "verify your account", "account locked", "urgent", "immediately",
    "password", "login", "confirm your identity", "update billing",
    "bank", "ssn", "security alert"
]

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl"
]

IP_URL_PATTERN = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}(\b|/)", re.IGNORECASE)
PUNYCODE_PATTERN = re.compile(r"xn--", re.IGNORECASE)

def keyword_rule(text: str) -> Tuple[int, List[str]]:
    t = (text or "").lower()
    hits = [k for k in SUSPICIOUS_KEYWORDS if k in t]
    if hits:
        return (25, [f"Suspicious keywords: {', '.join(hits[:3])}"])
    return (0, [])

def too_many_links_rule(urls: List[str]) -> Tuple[int, List[str]]:
    if len(urls) >= 5:
        return (20, [f"Excessive number of links: {len(urls)}"])
    return (0, [])

def ip_address_url_rule(urls: List[str]) -> Tuple[int, List[str]]:
    for u in urls:
        if IP_URL_PATTERN.search(u):
            return (30, ["URL uses IP address instead of domain"])
    return (0, [])

def punycode_rule(urls: List[str]) -> Tuple[int, List[str]]:
    for u in urls:
        if PUNYCODE_PATTERN.search(u):
            return (20, ["Punycode detected in URL (possible homograph attack)"])
    return (0, [])

def shortener_rule(urls: List[str]) -> Tuple[int, List[str]]:
    for u in urls:
        for d in SHORTENER_DOMAINS:
            if d in u.lower():
                return (15, [f"URL shortener detected: {d}"])
    return (0, [])
