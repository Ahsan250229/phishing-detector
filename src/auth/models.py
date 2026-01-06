# src/auth/models.py
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class UserRole(str, Enum):
    admin = "admin"
    analyst = "analyst"


class UserRecord(BaseModel):
    """
    Internal representation of a user. In Part 2 we can keep this in memory.
    Later you can map this to a DB model.
    """
    id: str
    username: str
    password_hash: str
    role: UserRole
    is_active: bool = True

    # 2FA fields
    otp_enabled: bool = False
    otp_secret: Optional[str] = None

    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


# ---------- API Schemas ----------

class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)
    role: UserRole = UserRole.analyst


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    requires_otp: bool = False


class OTPSetupResponse(BaseModel):
    """
    Return secret + provisioning URI. You can render this as QR in frontend.
    """
    otp_secret: str
    provisioning_uri: str


class OTPVerifyRequest(BaseModel):
    otp_code: str = Field(min_length=6, max_length=8)


class MessageResponse(BaseModel):
    message: str
