# src/storage/quarantine_store.py
from __future__ import annotations

from typing import Dict, Optional, List
from datetime import datetime

from src.models.quarantine import QuarantineRecord


_STORE: Dict[str, QuarantineRecord] = {}


def save_record(rec: QuarantineRecord) -> None:
    _STORE[rec.scan_id] = rec


def get_record(scan_id: str) -> Optional[QuarantineRecord]:
    return _STORE.get(scan_id)


def list_quarantined() -> List[QuarantineRecord]:
    return [r for r in _STORE.values() if r.status == "QUARANTINED"]


def release(scan_id: str) -> Optional[QuarantineRecord]:
    rec = _STORE.get(scan_id)
    if not rec:
        return None
    rec.status = "RELEASED"
    rec.released_at = datetime.utcnow()
    _STORE[scan_id] = rec
    return rec
