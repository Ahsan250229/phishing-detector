# src/admin/routes.py
from fastapi import APIRouter, Depends, HTTPException
from typing import Optional

from src.auth.dependencies import require_role
from src.auth.models import UserRecord, UserRole

from src.storage.quarantine_store import get_record, list_records, save_record, delete_record

router = APIRouter(prefix="/admin", tags=["admin"])

# ✅ RBAC enforcement: Admin only (also enforces OTP if otp_enabled=True)
admin_only = require_role(UserRole.admin)


@router.get("/quarantine")
def list_quarantine(
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    _admin: UserRecord = Depends(admin_only),
):
    """
    List quarantine records (admin only).
    Supports basic pagination + optional status filtering.
    """
    try:
        return list_records(status=status, limit=limit, offset=offset)
    except TypeError:
        # If your list_records signature differs, keep it simple:
        # fall back to list_records() and filter in memory if needed.
        data = list_records()
        if status:
            data = [r for r in data if getattr(r, "status", None) == status]
        return {"total": len(data), "limit": limit, "offset": offset, "items": data[offset:offset+limit]}


@router.get("/quarantine/{scan_id}")
def get_quarantine(
    scan_id: str,
    _admin: UserRecord = Depends(admin_only),
):
    rec = get_record(scan_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Quarantine record not found")
    return rec


@router.patch("/quarantine/{scan_id}")
def update_quarantine(
    scan_id: str,
    payload: dict,
    admin: UserRecord = Depends(admin_only),
):
    """
    Update quarantine record fields (admin only).
    Typical fields:
      - status: "released" | "confirmed_phishing" | "quarantined" | etc.
      - admin_notes: string
    """
    rec = get_record(scan_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Quarantine record not found")

    if "status" in payload:
        rec.status = payload["status"]
    if "admin_notes" in payload:
        rec.admin_notes = payload["admin_notes"]

    # Optional audit fields if your model supports them
    if hasattr(rec, "updated_by"):
        rec.updated_by = getattr(admin, "username", None)
    if hasattr(rec, "updated_at"):
        from datetime import datetime
        rec.updated_at = datetime.utcnow()

    save_record(rec)
    return {"scan_id": scan_id, "status": getattr(rec, "status", None), "updated_by": getattr(admin, "username", None)}


@router.delete("/quarantine/{scan_id}")
def delete_quarantine(
    scan_id: str,
    _admin: UserRecord = Depends(admin_only),
):
    ok = delete_record(scan_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Quarantine record not found")
    return {"deleted": True, "scan_id": scan_id}
