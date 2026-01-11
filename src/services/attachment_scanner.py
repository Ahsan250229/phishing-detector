# src/services/attachment_scanner.py
from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from typing import Dict, List, Tuple

from src.models.schemas import AttachmentIn


RISKY_EXTENSIONS = {
    ".exe", ".js", ".vbs", ".scr", ".bat", ".cmd", ".ps1",
    ".zip", ".rar", ".7z", ".iso", ".img",
    ".docm", ".xlsm", ".pptm",
}

DEFAULT_MAX_ATTACHMENT_BYTES = int(os.getenv("MAX_ATTACHMENT_BYTES", "5000000"))  # 5 MB each


def _ext(filename: str) -> str:
    return os.path.splitext(filename.lower().strip())[1]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def scan_attachments(attachments: List[AttachmentIn]) -> Tuple[int, List[str], List[Dict[str, object]]]:
    """
    Demo-grade attachment scanning:
    - base64 decode
    - size limits (DoS prevention)
    - sha256 hashing (evidence)
    - risky extension scoring
    Returns: (score, findings, details_list)
    """
    if not attachments:
        return 0, [], []

    findings: List[str] = []
    score = 0
    details: List[Dict[str, object]] = []

    for a in attachments:
        filename = a.filename.strip()
        ext = _ext(filename)

        try:
            raw = base64.b64decode(a.content_base64, validate=True)
        except Exception:
            findings.append(f"Attachment '{filename}' is not valid base64")
            score += 15
            details.append({"filename": filename, "error": "invalid_base64"})
            continue

        if len(raw) > DEFAULT_MAX_ATTACHMENT_BYTES:
            findings.append(f"Attachment '{filename}' exceeds max size ({DEFAULT_MAX_ATTACHMENT_BYTES} bytes)")
            score += 20
            details.append({"filename": filename, "size": len(raw), "error": "too_large"})
            continue

        h = _sha256(raw)

        # risky extension heuristic
        if ext in RISKY_EXTENSIONS:
            findings.append(f"Risky attachment type detected: {ext} ({filename})")
            score += 25

        # weak but useful heuristic: files with no extension
        if ext == "":
            findings.append(f"Attachment has no extension (suspicious): {filename}")
            score += 10

        details.append(
            {
                "filename": filename,
                "ext": ext,
                "size": len(raw),
                "sha256": h,
            }
        )

    return score, findings, details
