import os
import secrets
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text

from .db import get_db
from .models import OwUser, OwPasswordReset
from .auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_token,
    token_hash,
    verify_token_hash,
)

logger = logging.getLogger(__name__)
router = APIRouter()


def utcnow() -> datetime:
    """Timezone-aware UTC now."""
    return datetime.now(timezone.utc)


def ensure_utc(dt: datetime | None) -> datetime | None:
    """Ensure datetime is timezone-aware UTC (handles naive values safely)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# -------------------------
# Config
# -------------------------
ENV = os.getenv("ENV", "development")

JWT_SECRET = os.getenv("JWT_SECRET", os.getenv("SECRET_KEY", "dev-secret"))
JWT_EXPIRES_MINUTES = int(os.getenv("JWT_EXPIRES_MINUTES", "60"))

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5500")
PUBLIC_APP_URL = os.getenv("PUBLIC_APP_URL", FRONTEND_URL)

EMAIL_FROM = os.getenv("EMAIL_FROM", "no-reply@example.com")
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")

VERIFY_TOKEN_TTL_MIN = int(os.getenv("VERIFY_TOKEN_TTL_MIN", "60"))
RESET_TOKEN_TTL_MIN = int(os.getenv("RESET_TOKEN_TTL_MIN", "30"))


# -------------------------
# Helpers
# -------------------------
def _send_email(to_email: str, subject: str, html_body: str):
    """Send email via SMTP (Gmail app password supported)."""
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        raise RuntimeError("SMTP is not configured (missing SMTP_HOST/USER/PASS).")

    msg = MIMEMultipart("alternative")
    msg["From"] = EMAIL_FROM
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(html_body, "html"))

    # Gmail: STARTTLS on 587
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
        server.ehlo()
        if SMTP_PORT in (587, 25):
            server.starttls()
            server.ehlo()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(EMAIL_FROM, [to_email], msg.as_string())


def _make_verify_email_link(email: str, token: str) -> str:
    return f"{PUBLIC_APP_URL}/tech.html?mode=verify&email={email}&token={token}#workbench"


def _make_reset_email_link(email: str, token: str) -> str:
    return f"{PUBLIC_APP_URL}/tech.html?mode=reset&email={email}&token={token}#workbench"


def _user_has_inline_reset_tokens() -> bool:
    """
    If OwUser has reset_token_hash/reset_expires_at columns (inline reset),
    prefer that path; otherwise fallback to OwPasswordReset table.
    """
    return hasattr(OwUser, "reset_token_hash") and hasattr(OwUser, "reset_expires_at")


# -------------------------
# Schemas (Pydantic)
# -------------------------
from pydantic import BaseModel, EmailStr


class RegisterIn(BaseModel):
    email: EmailStr
    password: str


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class ResendVerifyIn(BaseModel):
    email: EmailStr


class VerifyIn(BaseModel):
    email: EmailStr
    token: str


class ForgotIn(BaseModel):
    email: EmailStr


class ResetPasswordIn(BaseModel):
    email: EmailStr
    token: str
    new_password: str


# -------------------------
# Routes
# -------------------------
@router.post("/auth/register")
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    password = payload.password

    existing = db.query(OwUser).filter(OwUser.email == email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    verify_token = secrets.token_urlsafe(32)
    now = utcnow()
    expires = now + timedelta(minutes=VERIFY_TOKEN_TTL_MIN)

    user = OwUser(
        email=email,
        hashed_password=hash_password(password),
        is_email_verified=False,
        verify_token_hash=token_hash(verify_token),
        verify_expires_at=expires,
        created_at=now,
        updated_at=now,
    )
    db.add(user)
    db.commit()

    link = _make_verify_email_link(email, verify_token)
    subject = "Verify your email"
    body = f"""
    <p>Hi,</p>
    <p>Please verify your email by clicking the link below:</p>
    <p><a href="{link}">Verify email</a></p>
    <p>This link expires in {VERIFY_TOKEN_TTL_MIN} minutes.</p>
    """

    try:
        _send_email(email, subject, body)
    except Exception as e:
        logger.exception("EMAIL_SEND_FAILED(register): %s", e)

    return {"ok": True}


@router.post("/auth/login")
def login(payload: LoginIn, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    user = db.query(OwUser).filter(OwUser.email == email).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Require verified email
    if not user.is_email_verified:
        raise HTTPException(status_code=403, detail="Email not verified")

    token = create_access_token({"sub": str(user.id), "email": user.email}, JWT_SECRET, JWT_EXPIRES_MINUTES)
    return {"access_token": token, "token_type": "bearer"}


@router.post("/auth/resend-verify")
def resend_verify(payload: ResendVerifyIn, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    user = db.query(OwUser).filter(OwUser.email == email).first()

    # Always respond OK to avoid email enumeration
    if not user or user.is_email_verified:
        return {"ok": True}

    verify_token = secrets.token_urlsafe(32)
    now = utcnow()
    user.verify_token_hash = token_hash(verify_token)
    user.verify_expires_at = now + timedelta(minutes=VERIFY_TOKEN_TTL_MIN)
    user.updated_at = now
    db.add(user)
    db.commit()

    link = _make_verify_email_link(email, verify_token)
    subject = "Verify your email"
    body = f"""
    <p>Hi,</p>
    <p>Here is your new verification link:</p>
    <p><a href="{link}">Verify email</a></p>
    <p>This link expires in {VERIFY_TOKEN_TTL_MIN} minutes.</p>
    """

    try:
        _send_email(email, subject, body)
    except Exception as e:
        logger.exception("EMAIL_SEND_FAILED(resend_verify): %s", e)

    return {"ok": True}


@router.post("/auth/verify")
def verify_email(payload: VerifyIn, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    token = payload.token.strip()

    user = db.query(OwUser).filter(OwUser.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid verification request")

    vhash = user.verify_token_hash
    vexp = user.verify_expires_at
    now = utcnow()

    vexp_utc = ensure_utc(vexp)
    if (not vhash) or (not vexp_utc) or (vexp_utc <= now):
        raise HTTPException(status_code=400, detail="Verification token expired or invalid")

    if not verify_token_hash(token, vhash):
        raise HTTPException(status_code=400, detail="Verification token invalid")

    user.is_email_verified = True
    user.verify_token_hash = None
    user.verify_expires_at = None
    user.updated_at = now
    db.add(user)
    db.commit()
    return {"ok": True}


@router.post("/auth/forgot")
def forgot_password(payload: ForgotIn, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    user = db.query(OwUser).filter(OwUser.email == email).first()

    # Always respond OK
    if not user:
        return {"ok": True}

    reset_token = secrets.token_urlsafe(32)
    now = utcnow()
    exp = now + timedelta(minutes=RESET_TOKEN_TTL_MIN)

    # Option A: inline reset token on user
    if _user_has_inline_reset_tokens():
        user.reset_token_hash = token_hash(reset_token)
        user.reset_expires_at = exp
        user.updated_at = now
        db.add(user)
        db.commit()
    else:
        # Option B: separate table
        reset = OwPasswordReset(
            email=email,
            token_hash=token_hash(reset_token),
            expires_at=exp,
            used=False,
            created_at=now,
        )
        db.add(reset)
        db.commit()

    link = _make_reset_email_link(email, reset_token)
    subject = "Reset your password"
    body = f"""
    <p>Hi,</p>
    <p>Click below to reset your password:</p>
    <p><a href="{link}">Reset password</a></p>
    <p>This link expires in {RESET_TOKEN_TTL_MIN} minutes.</p>
    """

    try:
        _send_email(email, subject, body)
    except Exception as e:
        logger.exception("EMAIL_SEND_FAILED(forgot): %s", e)

    return {"ok": True}


@router.post("/auth/reset")
def reset_password(payload: ResetPasswordIn, db: Session = Depends(get_db)):
    email = (payload.email or "").strip().lower()
    token = (payload.token or "").strip()
    new_pw = payload.new_password

    if not email or not token or not new_pw:
        raise HTTPException(status_code=400, detail="Missing fields")

    now = utcnow()

    # Option A: inline reset token on user record
    if _user_has_inline_reset_tokens():
        user = db.query(OwUser).filter(OwUser.email == email).first()
        if not user:
            return {"ok": True}  # do not leak existence

        rhash = user.reset_token_hash
        rexp = user.reset_expires_at
        rexp_utc = ensure_utc(rexp)

        if (not rhash) or (not rexp_utc) or (rexp_utc <= now):
            raise HTTPException(status_code=400, detail="Reset token expired or invalid")

        if not verify_token_hash(token, rhash):
            raise HTTPException(status_code=400, detail="Reset token invalid")

        user.hashed_password = hash_password(new_pw)
        user.reset_token_hash = None
        user.reset_expires_at = None
        user.updated_at = now
        db.add(user)
        db.commit()
        return {"ok": True}

    # Option B: separate PasswordReset table
    reset = (
        db.query(OwPasswordReset)
        .filter(OwPasswordReset.email == email, OwPasswordReset.used == False)  # noqa: E712
        .order_by(OwPasswordReset.created_at.desc())
        .first()
    )
    if not reset:
        raise HTTPException(status_code=400, detail="Reset token expired or invalid")

    reset_exp_utc = ensure_utc(reset.expires_at)
    if (not reset_exp_utc) or (reset_exp_utc <= now):
        raise HTTPException(status_code=400, detail="Reset token expired or invalid")

    if not verify_token_hash(token, reset.token_hash):
        raise HTTPException(status_code=400, detail="Reset token invalid")

    user = db.query(OwUser).filter(OwUser.email == email).first()
    if not user:
        return {"ok": True}

    user.hashed_password = hash_password(new_pw)
    user.updated_at = now
    reset.used = True
    reset.used_at = now
    db.add_all([user, reset])
    db.commit()
    return {"ok": True}
