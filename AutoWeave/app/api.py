# app/api.py
import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from .db import get_db
from .models import OwUser, OwPasswordReset
from .mailer import send_email  # assumes you already have this

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def utcnow():
    return datetime.now(timezone.utc)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def new_token_urlsafe(nbytes: int = 24) -> str:
    return secrets.token_urlsafe(nbytes)


def frontend_url() -> str:
    return (os.getenv("FRONTEND_URL") or os.getenv("PUBLIC_APP_URL") or "").rstrip("/")


# ---------- Schemas ----------

class EmailOnly(BaseModel):
    email: EmailStr


class VerifyRequest(BaseModel):
    email: EmailStr
    token: str


class ForgotRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    token: str
    new_password: str


# ---------- Password hashing ----------
# Keep using passlib if you already do; here’s a minimal hook point.
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(pw: str) -> str:
    return pwd_context.hash(pw)

def verify_password(pw: str, pw_hash: str) -> bool:
    return pwd_context.verify(pw, pw_hash)


# ---------- Email templates ----------

def build_verify_link(email: str, token: str) -> str:
    # your frontend already uses tech.html?mode=verify&email=...&token=...
    base = frontend_url()
    if not base:
        return ""
    return f"{base}/tech.html?mode=verify&email={email}&token={token}#workbench"


def build_reset_link(email: str, token: str) -> str:
    base = frontend_url()
    if not base:
        return ""
    return f"{base}/tech.html?mode=reset&email={email}&token={token}#workbench"


# ---------- Endpoints ----------

@router.post("/resend-verify")
def resend_verify(payload: EmailOnly, db: Session = Depends(get_db)):
    """
    Re-issue verification email if user exists and is not verified.
    """
    email = payload.email.lower().strip()
    user = db.query(OwUser).filter(OwUser.email == email).first()

    # Always return 200 (don’t leak whether user exists)
    if not user:
        return {"ok": True}

    if user.is_verified:
        return {"ok": True}

    token = new_token_urlsafe()
    user.verify_hash = sha256_hex(token)
    user.verify_expires_at = utcnow() + timedelta(hours=24)
    user.updated_at = utcnow()
    db.add(user)
    db.commit()

    link = build_verify_link(user.email, token)
    if link:
        send_email(
            to_email=user.email,
            subject="Verify your email",
            text=f"Click to verify: {link}\n\nIf you didn't request this, ignore this email.",
        )

    return {"ok": True}


@router.post("/verify")
def verify_email(payload: VerifyRequest, db: Session = Depends(get_db)):
    """
    Confirm verification token.
    Fixes: offset-naive vs offset-aware datetime comparisons.
    """
    email = payload.email.lower().strip()
    token = payload.token.strip()
    token_hash = sha256_hex(token)
    now = utcnow()

    user = db.query(OwUser).filter(OwUser.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid token")

    vhash = user.verify_hash
    vexp = user.verify_expires_at

    # vexp is timezone-aware (TIMESTAMPTZ) now; now is timezone-aware UTC
    if (not vhash) or (not vexp) or (vexp <= now) or (vhash != token_hash):
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    user.is_verified = True
    user.verify_hash = None
    user.verify_expires_at = None
    user.updated_at = now
    db.add(user)
    db.commit()

    return {"ok": True}


@router.post("/forgot")
def forgot_password(payload: ForgotRequest, db: Session = Depends(get_db)):
    """
    Send reset link if account exists.
    """
    email = payload.email.lower().strip()
    user = db.query(OwUser).filter(OwUser.email == email).first()

    # Always 200
    if not user:
        return {"ok": True}

    token = new_token_urlsafe()
    token_hash = sha256_hex(token)

    # Store on user (simple) OR use table; here we do both to keep options open
    user.reset_hash = token_hash
    user.reset_expires_at = utcnow() + timedelta(hours=2)
    user.updated_at = utcnow()
    db.add(user)

    # Optional audit row
    db.add(OwPasswordReset(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=user.reset_expires_at,
    ))

    db.commit()

    link = build_reset_link(user.email, token)
    if link:
        send_email(
            to_email=user.email,
            subject="Reset your password",
            text=f"Reset link: {link}\n\nIf you didn't request this, ignore this email.",
        )

    return {"ok": True}