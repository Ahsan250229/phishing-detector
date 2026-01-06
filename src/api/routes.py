import os
import uuid
from fastapi import APIRouter
from src.models.schemas import ScanRequest, ScanResponse
from src.core.detector import analyze_email

router = APIRouter()

MAX_EMAIL_CHARS = int(os.getenv("MAX_EMAIL_CHARS", "20000"))

@router.get("/health")
def health():
    return {"status": "ok", "service": "phishing-detector", "version": "0.1.0"}

@router.post("/scan-email", response_model=ScanResponse)
def scan_email(payload: ScanRequest):
    # Basic DoS prevention
    if len(payload.email_text) > MAX_EMAIL_CHARS:
        return ScanResponse(
            verdict="REJECTED",
            score=0,
            reasons=[f"Email content too large (max {MAX_EMAIL_CHARS} chars)"],
            urls=[],
            request_id=str(uuid.uuid4()),
        )

    result = analyze_email(payload.email_text)
    return ScanResponse(
        verdict=result["verdict"],
        score=result["score"],
        reasons=result["reasons"],
        urls=result["urls"],
        request_id=str(uuid.uuid4()),
    )
