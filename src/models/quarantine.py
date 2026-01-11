# src/models/quarantine.py
from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Literal, Dict
from pydantic import BaseModel, Field

Verdict = Literal["SAFE", "SUSPICIOUS", "PHISHING", "REJECTED"]
QuarantineStatus = Literal["STORED", "QUARANTINED", "RELEASED"]


class QuarantineRecord(BaseModel):
    scan_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

    verdict: Verdict
    score: int
    reasons: List[str]
    urls: List[str]

    header_score: int = 0
    header_findings: List[str] = []
    attachment_score: int = 0
    attachment_findings: List[str] = []

    status: QuarantineStatus = "STORED"
    released_at: Optional[datetime] = None

    # Optional raw evidence for exports
    header_details: Optional[Dict[str, object]] = None
    attachment_details: Optional[List[Dict[str, object]]] = None
