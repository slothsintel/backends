from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from .auth import (
    create_access_token,
    hash_password,
    verify_password,
)
from .db import get_db
from .mailer import send_email
from .models import OwPasswordReset, OwUser

router = APIRouter(prefix="/api/v1")


# -----------------------------
# Helpers
# -----------------------------
def utcnow() -> datetime:
    # Always timezone-aware UTC
    return datetime.now(timezone.utc)


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """
    Ensure a datetime is timezone-aware (UTC).
    Handles old rows that may have been stored naive.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _public_app_url() -> str:
    return (os.getenv("PUBLIC_APP_URL") or os.getenv("FRONTEND_URL") or "").rstrip("/")


def _make_verify_link(email: str, token: str) -> str:
    app = _public_app_url()
    if not app:
        # still return something meaningful for logs
        return f"/tech.html?mode=verify&email={email}&token={token}"
    return f"{app}/tech.html?mode=verify&email={email}&token={token}"


def _make_reset_link(email: str, token: str) -> str:
    app = _public_app_url()
    if not app:
        return f"/tech.html?mode=reset&email={email}&token={token}"
    return f"{app}/tech.html?mode=reset&email={email}&token={token}"


# -----------------------------
# Schemas
# -----------------------------
class LoginIn(BaseModel):
    email: EmailStr
    password: str


class RegisterIn(BaseModel):
    email: EmailStr
    password: str


class EmailOnly(BaseModel):
    email: EmailStr


class VerifyIn(BaseModel):
    email: EmailStr
    token: str


class ResetIn(BaseModel):
    email: EmailStr
    token: str
    new_password: str


# -----------------------------
# Auth endpoints
# -----------------------------
@router.post("/auth/register")
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    pw_hash = hash_password(payload.password)

    existing = db.query(OwUser).filter(OwUser.email == email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered.")

    user = OwUser(
        email=email,
        password_hash=pw_hash,
        is_verified=False,
        created_at=utcnow(),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Create verify token + email
    token_plain = os.urandom(24).hex()
    user.verify_token_hash = hash_password(token_plain)
    user.verify_expires_at = utcnow() + timedelta(hours=24)
    db.commit()

    try:
        link = _make_verify_link(email, token_plain)
        send_email(
            to_email=email,
            subject="Verify your email",
            text_body=f"Welcome to AutoWeave.\n\nVerify your email:\n{link}\n\nThis link expires in 24 hours.",
        )
    except Exception as e:
        # Don't block registration if email fails; user can resend.
        print(f"EMAIL_SEND_FAILED(register_verify): {repr(e)}")

    return {"ok": True, "message": "Registered. Please check your email to verify."}


@router.post("/auth/login")
def login(payload: LoginIn, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    user = db.query(OwUser).filter(OwUser.email == email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Email not verified.")

    token = create_access_token(user.id)
    return {"access_token": token, "token_type": "bearer"}


@router.post("/auth/resend-verify")
def resend_verify(payload: EmailOnly, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    user = db.query(OwUser).filter(OwUser.email == email).first()

    # Always respond 200-ish to avoid user enumeration
    if not user:
        return {"ok": True, "message": "If the account exists, a verification email has been sent."}

    if user.is_verified:
        return {"ok": True, "message": "Email already verified."}

    token_plain = os.urandom(24).hex()
    user.verify_token_hash = hash_password(token_plain)
    user.verify_expires_at = utcnow() + timedelta(hours=24)
    db.commit()

    try:
        link = _make_verify_link(email, token_plain)
        send_email(
            to_email=email,
            subject="Verify your email",
            text_body=f"Verify your email:\n{link}\n\nThis link expires in 24 hours.",
        )
    except Exception as e:
        print(f"EMAIL_SEND_FAILED(resend_verify): {repr(e)}")

    return {"ok": True, "message": "If the account exists, a verification email has been sent."}


@router.post("/auth/verify")
def verify_email(payload: VerifyIn, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    token = payload.token.strip()

    user = db.query(OwUser).filter(OwUser.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid verification request.")

    vhash = user.verify_token_hash
    vexp = ensure_utc(user.verify_expires_at)
    now = utcnow()

    # Fix: both sides are offset-aware now
    if (not vhash) or (not vexp) or (vexp <= now):
        raise HTTPException(status_code=400, detail="Verification token expired. Please resend.")

    if not verify_password(token, vhash):
        raise HTTPException(status_code=400, detail="Invalid verification token.")

    user.is_verified = True
    user.verify_token_hash = None
    user.verify_expires_at = None
    db.commit()

    return {"ok": True, "message": "Email verified."}


@router.post("/auth/forgot")
def forgot_password(payload: EmailOnly, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    user = db.query(OwUser).filter(OwUser.email == email).first()

    # Always "success" to avoid user enumeration
    if not user:
        return {"ok": True, "message": "If that email exists, a reset link has been sent."}

    token_plain = os.urandom(24).hex()
    expires_at = utcnow() + timedelta(hours=1)

    # Upsert reset row
    row = db.query(OwPasswordReset).filter(OwPasswordReset.user_id == user.id).first()
    if not row:
        row = OwPasswordReset(user_id=user.id)
        db.add(row)

    row.reset_token_hash = hash_password(token_plain)
    row.reset_expires_at = expires_at
    row.created_at = utcnow()
    db.commit()

    try:
        link = _make_reset_link(email, token_plain)
        send_email(
            to_email=email,
            subject="Reset your password",
            text_body=f"Reset your password:\n{link}\n\nThis link expires in 1 hour.",
        )
    except Exception as e:
        print(f"EMAIL_SEND_FAILED(forgot): {repr(e)}")

    return {"ok": True, "message": "If that email exists, a reset link has been sent."}


@router.post("/auth/reset")
def reset_password(payload: ResetIn, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    token = payload.token.strip()

    user = db.query(OwUser).filter(OwUser.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid reset request.")

    row = db.query(OwPasswordReset).filter(OwPasswordReset.user_id == user.id).first()
    if not row:
        raise HTTPException(status_code=400, detail="Invalid reset request.")

    rexp = ensure_utc(row.reset_expires_at)
    now = utcnow()

    if (not row.reset_token_hash) or (not rexp) or (rexp <= now):
        raise HTTPException(status_code=400, detail="Reset token expired. Please request again.")

    if not verify_password(token, row.reset_token_hash):
        raise HTTPException(status_code=400, detail="Invalid reset token.")

    user.password_hash = hash_password(payload.new_password)

    # Invalidate token
    row.reset_token_hash = None
    row.reset_expires_at = None
    db.commit()

    return {"ok": True, "message": "Password updated."}
