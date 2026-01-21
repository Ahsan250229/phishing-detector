# src/auth/dependencies.py
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional, Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.auth.models import UserRecord, UserRole
from src.auth.utils import decode_token, hash_password
from src.db import db_conn, init_db

bearer_scheme = HTTPBearer(auto_error=True)


# -------------------------
# DB row -> UserRecord mapper
# -------------------------
def _row_to_user(row) -> UserRecord:
    """
    Maps SQLite row columns to the UserRecord model.
    IMPORTANT: DB uses `totp_secret` while the model uses `otp_secret`.
    """
    totp_secret = row["totp_secret"] if row["totp_secret"] is not None else None
    otp_enabled = bool(totp_secret and str(totp_secret).strip())

    return UserRecord(
        id=str(row["id"]),
        username=row["username"],
        password_hash=row["password_hash"],
        role=UserRole(row["role"].lower()) if isinstance(row["role"], str) else row["role"],
        otp_enabled=otp_enabled,
        otp_secret=totp_secret,
        is_active=bool(row["is_active"]),
        created_at=None,  # Not stored in current schema; keep None
        updated_at=None,  # Not stored in current schema; keep None
    )


# -------------------------
# Seed default admin in DB
# -------------------------
def _seed_default_admin() -> None:
    """
    Creates a default admin for local/dev demo if none exists.
    Username: admin
    Password: Admin@12345
    Role: ADMIN
    """
    init_db()  # ensures DB + table exist

    with db_conn() as conn:
        # Ensure sqlite rows behave like dicts (Row objects)
        try:
            conn.row_factory  # type: ignore[attr-defined]
        except Exception:
            pass

        row = conn.execute(
            "SELECT id FROM users WHERE username=?",
            ("admin",),
        ).fetchone()

        if row:
            return

        # Insert default admin (no OTP by default)
        conn.execute(
            """
            INSERT INTO users (username, password_hash, role, totp_secret, is_active)
            VALUES (?, ?, ?, ?, ?)
            """,
            ("admin", hash_password("Admin@12345"), "ADMIN", None, 1),
        )
        conn.commit()


_seed_default_admin()


# -------------------------
# Store helpers (DB-backed)
# -------------------------
def get_user_by_username(username: str) -> Optional[UserRecord]:
    init_db()
    with db_conn() as conn:
        conn.row_factory = __import__("sqlite3").Row  # enforce Row mapping
        row = conn.execute(
            """
            SELECT id, username, password_hash, role, totp_secret, is_active
            FROM users
            WHERE username=?
            """,
            (username,),
        ).fetchone()
    return _row_to_user(row) if row else None


def get_user_by_id(user_id: str) -> Optional[UserRecord]:
    init_db()
    with db_conn() as conn:
        conn.row_factory = __import__("sqlite3").Row
        row = conn.execute(
            """
            SELECT id, username, password_hash, role, totp_secret, is_active
            FROM users
            WHERE id=?
            """,
            (user_id,),
        ).fetchone()
    return _row_to_user(row) if row else None


def save_user(user: UserRecord) -> None:
    """
    Persists UserRecord changes back to SQLite.
    - Updates password_hash, role, totp_secret, is_active
    - If user.id is not an integer ID from DB, it will insert a new row.
      (Best practice: let DB assign integer IDs; register() should insert without custom id.)
    """
    init_db()

    # Normalize role to DB format
    role_str = user.role.value.upper() if hasattr(user.role, "value") else str(user.role).upper()

    # Normalize totp_secret storage
    totp_secret = (user.otp_secret or None)
    is_active_int = 1 if user.is_active else 0

    with db_conn() as conn:
        conn.row_factory = __import__("sqlite3").Row

        # If id is numeric and exists -> update; else update by username fallback; else insert.
        existing = None
        try:
            existing = conn.execute("SELECT id FROM users WHERE id=?", (user.id,)).fetchone()
        except Exception:
            existing = None

        if existing:
            conn.execute(
                """
                UPDATE users
                SET password_hash=?, role=?, totp_secret=?, is_active=?
                WHERE id=?
                """,
                (user.password_hash, role_str, totp_secret, is_active_int, user.id),
            )
        else:
            # Try update by username first (common with legacy uuid ids)
            row_u = conn.execute("SELECT id FROM users WHERE username=?", (user.username,)).fetchone()
            if row_u:
                conn.execute(
                    """
                    UPDATE users
                    SET password_hash=?, role=?, totp_secret=?, is_active=?
                    WHERE username=?
                    """,
                    (user.password_hash, role_str, totp_secret, is_active_int, user.username),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO users (username, password_hash, role, totp_secret, is_active)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (user.username, user.password_hash, role_str, totp_secret, is_active_int),
                )

        conn.commit()


# -------------------------
# Core auth dependency
# -------------------------
def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> UserRecord:
    """
    Base authentication dependency.
    - Validates JWT
    - Resolves user from DB
    - Attaches runtime OTP verification state from token claims
    """
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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    user = get_user_by_id(str(user_id))
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    # Runtime-only OTP verification flag (derived from token)
    user.__dict__["_otp_verified"] = bool(payload.get("otp_verified", False))

    return user


# -------------------------
# 2FA enforcement
# -------------------------
def require_otp_verified(
    user: UserRecord = Depends(get_current_user),
) -> UserRecord:
    """
    Enforces OTP verification if user has 2FA enabled (secret present).
    """
    if user.otp_enabled:
        otp_ok = bool(getattr(user, "_otp_verified", False))
        if not otp_ok:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="OTP verification required",
            )
    return user


# -------------------------
# RBAC enforcement
# -------------------------
def require_role(role: UserRole) -> Callable:
    """
    Enforces role-based access control.
    Implicitly enforces:
      - JWT authentication
      - OTP verification (if enabled)
    """
    def _dep(user: UserRecord = Depends(require_otp_verified)) -> UserRecord:
        if user.role != role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role",
            )
        return user

    return _dep
