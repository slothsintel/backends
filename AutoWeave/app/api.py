# app/api.py
import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from passlib.context import CryptContext

from .db import get_db
from .models import OwUser, OwPasswordReset
from .mailer import send_email
from .auth import create_access_token

# IMPORTANT:
# main.py mounts this router at prefix="/api/v1"
# so this router should be prefix="/auth" -> final URLs: /api/v1/auth/...
router = APIRouter(prefix="/auth", tags=["auth"])


# ------------------------
# Helpers
# ------------------------
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def new_token_urlsafe(nbytes: int = 24) -> str:
    return secrets.token_urlsafe(nbytes)


def frontend_url() -> str:
    # prefer your explicit FRONTEND_URL; fallback to PUBLIC_APP_URL
    return (os.getenv("FRONTEND_URL") or os.getenv("PUBLIC_APP_URL") or "").rstrip("/")


# ------------------------
# Schemas
# ------------------------
class EmailOnly(BaseModel):
    email: EmailStr


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class VerifyRequest(BaseModel):
    email: EmailStr
    token: str


class ForgotRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    token: str
    new_password: str


# ------------------------
# Password hashing
# ------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(pw: str) -> str:
    return pwd_context.hash(pw)


def verify_password(pw: str, pw_hash: str) -> bool:
    return pwd_context.verify(pw, pw_hash)


# ------------------------
# Email links
# ------------------------
def build_verify_link(email: str, token: str) -> str:
    base = frontend_url()
    if not base:
        return ""
    # Keep consistent with your frontend router/anchor
    return f"{base}/tech.html?mode=verify&email={email}&token={token}#workbench"


def build_reset_link(email: str, token: str) -> str:
    base = frontend_url()
    if not base:
        return ""
    return f"{base}/tech.html?mode=reset&email={email}&token={token}#workbench"


# ------------------------
# Endpoints
# ------------------------
@router.post("/register")
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    """
    Create account + send verification email.
    """
    email = payload.email.lower().strip()
    pw = payload.password

    if len(pw) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    existing = db.query(OwUser).filter(OwUser.email == email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = OwUser(
        email=email,
        password_hash=hash_password(pw),
        is_verified=False,
    )

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
            text_body=f"Click to verify: {link}\n\nIf you didn't request this, ignore this email.",
        )

    return {"ok": True}


@router.post("/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    """
    Login requires verified email. Returns JWT access token.
    """
    email = payload.email.lower().strip()
    user = db.query(OwUser).filter(OwUser.email == email).first()

    if (not user) or (not verify_password(payload.password, user.password_hash)):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Please verify your email before logging in")

    token = create_access_token(str(user.id))
    return {"access_token": token, "token_type": "bearer"}


@router.post("/resend-verify")
def resend_verify(payload: EmailOnly, db: Session = Depends(get_db)):
    """
    Re-issue verification email if user exists and is not verified.
    Always returns 200 to avoid leaking whether a user exists.
    """
    email = payload.email.lower().strip()
    user = db.query(OwUser).filter(OwUser.email == email).first()

    if not user or user.is_verified:
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
            text_body=f"Click to verify: {link}\n\nIf you didn't request this, ignore this email.",
        )

    return {"ok": True}


@router.post("/verify")
def verify_email(payload: VerifyRequest, db: Session = Depends(get_db)):
    """
    Confirm verification token.
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
    Always returns 200 to avoid leaking whether a user exists.
    """
    email = payload.email.lower().strip()
    user = db.query(OwUser).filter(OwUser.email == email).first()

    if not user:
        return {"ok": True}

    token = new_token_urlsafe()
    token_hash = sha256_hex(token)

    user.reset_hash = token_hash
    user.reset_expires_at = utcnow() + timedelta(hours=2)
    user.updated_at = utcnow()
    db.add(user)

    # Optional audit row
    db.add(
        OwPasswordReset(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=user.reset_expires_at,
        )
    )

    db.commit()

    link = build_reset_link(user.email, token)
    if link:
        send_email(
            to_email=user.email,
            subject="Reset your password",
            text_body=f"Reset link: {link}\n\nIf you didn't request this, ignore this email.",
        )

    return {"ok": True}


@router.post("/reset")
def reset_password(payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    """
    Reset password using email + token (sent via /forgot).
    """
    email = payload.email.lower().strip()
    token = payload.token.strip()
    now = utcnow()

    user = db.query(OwUser).filter(OwUser.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    token_hash = sha256_hex(token)
    if (
        (not user.reset_hash)
        or (not user.reset_expires_at)
        or (user.reset_expires_at <= now)
        or (user.reset_hash != token_hash)
    ):
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    if len(payload.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    user.password_hash = hash_password(payload.new_password)
    user.reset_hash = None
    user.reset_expires_at = None
    user.updated_at = now
    db.add(user)

    # Mark latest matching audit row as used (best-effort)
    pr = (
        db.query(OwPasswordReset)
        .filter(
            OwPasswordReset.user_id == user.id,
            OwPasswordReset.token_hash == token_hash,
            OwPasswordReset.used_at.is_(None),
        )
        .order_by(OwPasswordReset.id.desc())
        .first()
    )
    if pr:
        pr.used_at = now
        db.add(pr)

    db.commit()
    return {"ok": True}