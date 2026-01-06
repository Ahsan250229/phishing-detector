from typing import List, Literal
from pydantic import BaseModel, Field

Verdict = Literal["SAFE", "SUSPICIOUS", "PHISHING", "REJECTED"]

class ScanRequest(BaseModel):
    email_text: str = Field(..., min_length=1, description="Raw email content as plain text")

class ScanResponse(BaseModel):
    verdict: Verdict
    score: int
    reasons: List[str]
    urls: List[str]
    request_id: str
