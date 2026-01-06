# src/auth/otp.py
from __future__ import annotations

import pyotp


def generate_otp_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str, issuer: str = "PhishingDetector") -> str:
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def verify_otp_code(secret: str, otp_code: str) -> bool:
    """
    valid_window=1 tolerates small device clock drift (~30s).
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(otp_code, valid_window=1)
