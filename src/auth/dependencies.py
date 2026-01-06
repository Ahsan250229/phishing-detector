# src/auth/dependencies.py
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Dict, Optional, Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from auth.models import UserRecord, UserRole
from auth.utils import decode_token, hash_password

bearer_scheme = HTTPBearer(auto_error=True)

# -------------------------
# In-memory user "database"
# -------------------------
_USERS: Dict[str, UserRecord] = {}


def _seed_default_admin() -> None:
    """
    Creates a default admin for local/dev demo if none exists.
    Username: admin
    Password: Admin@12345
    """
    if any(u.username == "admin" for u in _USERS.values()):
        return

    admin = UserRecord(
        id=str(uuid.uuid4()),
        username="admin",
        password_hash=hash_password("Admin@12345"),
        role=UserRole.admin,
        otp_enabled=False,
        otp_secret=None,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    _USERS[admin.id] = admin


_seed_default_admin()


# ---- helper functions to access store ----

def get_user_by_username(username: str) -> Optional[UserRecord]:
    return next((u for u in _USERS.values() if u.username == username), None)


def get_user_by_id(user_id: str) -> Optional[UserRecord]:
    return _USERS.get(user_id)


def save_user(user: UserRecord) -> None:
    user.updated_at = datetime.utcnow()
    _USERS[user.id] = user


# -------------------------
# Auth dependencies
# -------------------------

def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> UserRecord:
    token = creds.credentials
    try:
        payload = decode_token(token)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    user = get_user_by_id(user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    # Attach OTP state from token (not persisted)
    # If otp_enabled is True, we require otp_verified in token for protected routes.
    otp_verified = bool(payload.get("otp_verified", False))
    # We won't mutate user model; we'll enforce in a separate dependency.
    user.__dict__["_otp_verified"] = otp_verified  # internal runtime flag

    return user


def require_otp_verified(user: UserRecord = Depends(get_current_user)) -> UserRecord:
    """
    If user has 2FA enabled, block unless token indicates otp_verified=True.
    """
    if user.otp_enabled:
        otp_ok = bool(getattr(user, "_otp_verified", False))
        if not otp_ok:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="OTP verification required",
            )
    return user


def require_role(role: UserRole) -> Callable:
    def _dep(user: UserRecord = Depends(require_otp_verified)) -> UserRecord:
        if user.role != role:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return user
    return _dep
