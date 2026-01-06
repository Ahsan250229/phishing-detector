# src/auth/routes.py
from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from auth.models import (
    LoginRequest,
    MessageResponse,
    OTPSetupResponse,
    OTPVerifyRequest,
    RegisterRequest,
    TokenResponse,
    UserRecord,
    UserRole,
)
from auth.otp import generate_otp_secret, provisioning_uri, verify_otp_code
from auth.utils import create_access_token, hash_password, verify_password
from auth.dependencies import (
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
    user = get_user_by_username(payload.username)
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Create token; if OTP enabled, require OTP verification later.
    token = create_access_token(
        subject=user.id,
        extra_claims={
            "username": user.username,
            "role": user.role.value,
            "otp_verified": False,  # upgraded after OTP verify
        },
    )
    return TokenResponse(access_token=token, requires_otp=user.otp_enabled)


@router.post("/otp/setup", response_model=OTPSetupResponse)
def otp_setup(user: UserRecord = Depends(get_current_user)) -> OTPSetupResponse:
    """
    Generates OTP secret and enables 2FA for the current user.
    In a real system you may require re-authentication for this action.
    """
    secret = generate_otp_secret()
    user.otp_secret = secret
    user.otp_enabled = True
    save_user(user)

    uri = provisioning_uri(secret=secret, username=user.username, issuer="PhishingDetector")
    return OTPSetupResponse(otp_secret=secret, provisioning_uri=uri)


@router.post("/otp/verify", response_model=TokenResponse)
def otp_verify(payload: OTPVerifyRequest, user: UserRecord = Depends(get_current_user)) -> TokenResponse:
    """
    Verify user OTP and return upgraded token with otp_verified=true.
    """
    if not user.otp_enabled or not user.otp_secret:
        raise HTTPException(status_code=400, detail="OTP not enabled for this user")

    if not verify_otp_code(user.otp_secret, payload.otp_code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP code")

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
