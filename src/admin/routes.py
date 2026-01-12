from fastapi import APIRouter, Depends
from src.auth.dependencies import require_admin, TokenUser

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
)

@router.get("/quarantine")
def list_quarantine(admin: TokenUser = Depends(require_admin)):
    return {"items": []}

@router.get("/quarantine/{scan_id}")
def get_quarantine(scan_id: str, admin: TokenUser = Depends(require_admin)):
    return {"scan_id": scan_id}

@router.patch("/quarantine/{scan_id}")
def update_quarantine(scan_id: str, payload: dict, admin: TokenUser = Depends(require_admin)):
    return {"scan_id": scan_id, "updated_by": admin.sub}

@router.delete("/quarantine/{scan_id}")
def delete_quarantine(scan_id: str, admin: TokenUser = Depends(require_admin)):
    return {"deleted": True, "scan_id": scan_id}
