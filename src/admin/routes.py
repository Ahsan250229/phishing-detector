# src/admin/routes.py
from fastapi import APIRouter, Depends, HTTPException
from typing import Optional, List

from src.auth.dependencies import require_role
from src.auth.models import UserRecord, UserRole

from src.storage.quarantine_store import get_record, list_quarantined, release

router = APIRouter(prefix="/admin", tags=["admin"])

# ✅ Admin-only (JWT + OTP (if enabled) + RBAC)
admin_only = require_role(UserRole.admin)


@router.get("/quarantine")
def list_quarantine(
    _admin: UserRecord = Depends(admin_only),
):
    # Lists only quarantined records (your store supports this)
    items = list_quarantined()
    return {"total": len(items), "items": items}


@router.get("/quarantine/{scan_id}")
def get_quarantine(
    scan_id: str,
    _admin: UserRecord = Depends(admin_only),
):
    rec = get_record(scan_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Quarantine record not found")
    return rec


@router.post("/quarantine/{scan_id}/release")
def release_quarantine(
    scan_id: str,
    _admin: UserRecord = Depends(admin_only),
):
    rec = release(scan_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Quarantine record not found")
    return rec
