from typing import Dict, List
from src.services.url_extractor import extract_urls
from src.core import rules

def classify(score: int) -> str:
    if score >= 60:
        return "PHISHING"
    if score >= 30:
        return "SUSPICIOUS"
    return "SAFE"

def analyze_email(email_text: str) -> Dict[str, object]:
    urls: List[str] = extract_urls(email_text)

    score = 0
    reasons: List[str] = []

    for rule_fn in [
        lambda: rules.keyword_rule(email_text),
        lambda: rules.too_many_links_rule(urls),
        lambda: rules.ip_address_url_rule(urls),
        lambda: rules.punycode_rule(urls),
        lambda: rules.shortener_rule(urls),
    ]:
        pts, msgs = rule_fn()
        score += pts
        reasons.extend(msgs)

    verdict = classify(score)
    if verdict == "SAFE" and not reasons:
        reasons = ["No suspicious indicators detected"]

    return {
        "verdict": verdict,
        "score": int(score),
        "reasons": reasons,
        "urls": urls,
    }
