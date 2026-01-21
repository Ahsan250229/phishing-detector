# src/auth/routes.py
from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status

from src.auth.models import (
    LoginRequest,
    MessageResponse,
    OTPSetupResponse,
    OTPVerifyRequest,
    RegisterRequest,
    TokenResponse,
    UserRecord,
    UserRole,
)
from src.auth.otp import generate_otp_secret, provisioning_uri, verify_otp_code
from src.auth.utils import create_access_token, hash_password, verify_password
from src.auth.dependencies import (
    get_current_user,
    get_user_by_username,
    save_user,
    require_role,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=MessageResponse)
def register(payload: RegisterRequest) -> MessageResponse:
    """
    Demo registration. For production, restrict this to admin-only.
    """
    if get_user_by_username(payload.username):
        raise HTTPException(status_code=400, detail="Username already exists")

    user = UserRecord(
        id=str(uuid.uuid4()),
        username=payload.username,
        password_hash=hash_password(payload.password),
        role=payload.role,
        otp_enabled=False,
        otp_secret=None,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    save_user(user)
    return MessageResponse(message="User registered successfully")


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest) -> TokenResponse:
    """
    Step A3 - /auth/login
    - Accept username + password
    - Load user record
    - Verify password hash
    - Decide if 2FA is required
      * If 2FA NOT required -> issue normal JWT
      * If 2FA required -> return requires_otp=True and issue ONLY an OTP-pending token
    """
    user = get_user_by_username(payload.username)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # 2FA decision: prefer secret presence (examiner-friendly).
    # IMPORTANT: ensure your dependencies map DB 'totp_secret' -> model 'otp_secret'.
    otp_secret = (getattr(user, "otp_secret", None) or "").strip()
    requires_otp = len(otp_secret) > 0

    if not requires_otp:
        # No 2FA: issue final token immediately.
        token = create_access_token(
            subject=user.id,
            extra_claims={
                "username": user.username,
                "role": user.role.value,
                "otp_verified": False,
            },
        )
        return TokenResponse(access_token=token, requires_otp=False)

    # 2FA required:
    # Return requires_otp=True and issue ONLY an OTP-pending token (temporary).
    # We return it in access_token to avoid changing your TokenResponse model.
    # Your otp_verify endpoint should then "upgrade" to a final token.
    temp_token = create_access_token(
        subject=user.id,
        extra_claims={
            "username": user.username,
            "role": user.role.value,
            "otp_verified": False,
            "type": "otp_pending",
        },
        # If your create_access_token supports expiry override, uncomment and use it:
        # expires_minutes=5,
    )
    return TokenResponse(access_token=temp_token, requires_otp=True)


@router.post("/otp/setup", response_model=OTPSetupResponse)
def otp_setup(user: UserRecord = Depends(get_current_user)) -> OTPSetupResponse:
    """
    Generates OTP secret and enables 2FA for the current user.
    """
    secret = generate_otp_secret()

    user.otp_secret = secret
    user.otp_enabled = True
    user.updated_at = datetime.utcnow()
    save_user(user)

    uri = provisioning_uri(secret=secret, username=user.username, issuer="PhishingDetector")
    return OTPSetupResponse(otp_secret=secret, provisioning_uri=uri)


@router.post("/otp/verify", response_model=TokenResponse)
def otp_verify(
    payload: OTPVerifyRequest,
    user: UserRecord = Depends(get_current_user),
) -> TokenResponse:
    """
    Verify user OTP and return upgraded token with otp_verified=true.
    """
    otp_secret = (getattr(user, "otp_secret", None) or "").strip()
    if not otp_secret:
        raise HTTPException(status_code=400, detail="OTP not enabled for this user")

    if not verify_otp_code(otp_secret, payload.otp_code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid OTP code",
        )

    token = create_access_token(
        subject=user.id,
        extra_claims={
            "username": user.username,
            "role": user.role.value,
            "otp_verified": True,
        },
    )
    return TokenResponse(access_token=token, requires_otp=False)


@router.get("/me")
def me(user: UserRecord = Depends(get_current_user)):
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role.value,
        "otp_enabled": user.otp_enabled,
    }


# Example admin-only endpoint (RBAC)
@router.get("/admin/ping", response_model=MessageResponse)
def admin_ping(_: UserRecord = Depends(require_role(UserRole.admin))) -> MessageResponse:
    return MessageResponse(message="admin ok")
