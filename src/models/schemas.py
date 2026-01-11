# src/models/schemas.py
from __future__ import annotations

import base64
from typing import List, Literal, Optional
from pydantic import BaseModel, Field

Verdict = Literal["SAFE", "SUSPICIOUS", "PHISHING", "REJECTED"]


class AttachmentIn(BaseModel):
    filename: str = Field(..., min_length=1, description="Original attachment filename")
    content_base64: str = Field(..., min_length=1, description="Attachment bytes encoded as base64")


class ScanRequest(BaseModel):
    email_text: str = Field(..., min_length=1, description="Raw email content as plain text")
    email_headers: Optional[str] = Field(None, description="Raw email headers as text (optional)")
    attachments: Optional[List[AttachmentIn]] = Field(None, description="Optional attachments (base64 encoded)")


class ScanResponse(BaseModel):
    verdict: Verdict
    score: int
    reasons: List[str]
    urls: List[str]

    # New evidence fields
    header_score: int = 0
    header_findings: List[str] = []
    attachment_score: int = 0
    attachment_findings: List[str] = []

    # IDs
    scan_id: str
    request_id: str
