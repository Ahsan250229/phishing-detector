from src.core.detector import analyze_email

def test_safe_email():
    text = "Hi team, meeting is at 3pm. See you then."
    result = analyze_email(text)
    assert result["verdict"] in ["SAFE", "SUSPICIOUS", "PHISHING"]
    assert result["score"] >= 0
    assert isinstance(result["reasons"], list)

def test_phishing_keywords():
    text = "URGENT: verify your account immediately. Please login and update billing."
    result = analyze_email(text)
    assert result["score"] >= 25
    assert result["verdict"] in ["SUSPICIOUS", "PHISHING"]

def test_ip_url_detected():
    text = "Click now: http://192.168.1.10/login to confirm your identity"
    result = analyze_email(text)
    assert result["verdict"] in ["SUSPICIOUS", "PHISHING"]
    assert any("IP address" in r for r in result["reasons"])
