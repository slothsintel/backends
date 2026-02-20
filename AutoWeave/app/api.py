import os
import secrets
import hashlib
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import get_db
from .models import User, PasswordReset
from .auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
)

router = APIRouter()

# ----- config -----
FRONTEND_URL = os.getenv("FRONTEND_URL", "").rstrip("/")
PUBLIC_APP_URL = os.getenv("PUBLIC_APP_URL", FRONTEND_URL).rstrip("/")
SECRET_KEY = os.getenv("SECRET_KEY", "")
JWT_SECRET = os.getenv("JWT_SECRET", SECRET_KEY)

EMAIL_FROM = os.getenv("EMAIL_FROM", os.getenv("SMTP_USER", "")).strip()
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")

VERIFY_TTL_HOURS = int(os.getenv("VERIFY_TTL_HOURS", "24"))
RESET_TTL_HOURS = int(os.getenv("RESET_TTL_HOURS", "2"))


def utcnow() -> datetime:
    """Timezone-aware UTC 'now'. Avoid naive/aware datetime comparison bugs."""
    return datetime.now(timezone.utc)


def to_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Coerce a datetime from DB into timezone-aware UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# ----- helpers -----
def _send_email(to_email: str, subject: str, body: str) -> None:
    if not (SMTP_HOST and SMTP_USER and SMTP_PASS and EMAIL_FROM):
        raise RuntimeError("SMTP is not configured (SMTP_HOST/USER/PASS/EMAIL_FROM).")

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = to_email

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
        server.ehlo()
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(EMAIL_FROM, [to_email], msg.as_string())


def _new_token() -> str:
    return secrets.token_urlsafe(32)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _verify_link(email: str, token: str) -> str:
    # front-end consumes: tech.html?mode=verify&email=...&token=...
    base = PUBLIC_APP_URL or FRONTEND_URL
    return f"{base}/tech.html?mode=verify&email={email}&token={token}#workbench"


def _reset_link(email: str, token: str) -> str:
    base = PUBLIC_APP_URL or FRONTEND_URL
    return f"{base}/tech.html?mode=reset&email={email}&token={token}#workbench"


# ----- schemas -----
class RegisterIn(BaseModel):
    email: EmailStr
    password: str


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class ResendVerifyIn(BaseModel):
    email: EmailStr


class ForgotIn(BaseModel):
    email: EmailStr


class VerifyIn(BaseModel):
    email: EmailStr
    token: str


class ResetIn(BaseModel):
    email: EmailStr
    token: str
    new_password: str


# ----- routes -----
@router.post("/auth/register")
def register(data: RegisterIn, db: Session = Depends(get_db)):
    email = data.email.lower().strip()

    existing = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered.")

    raw_token = _new_token()
    vhash = _hash_token(raw_token)
    vexp = utcnow() + timedelta(hours=VERIFY_TTL_HOURS)

    user = User(
        email=email,
        password_hash=hash_password(data.password),
        is_verified=False,
        verify_hash=vhash,
        verify_expires_at=vexp,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    db.add(user)
    db.commit()

    # send verify
    try:
        link = _verify_link(email, raw_token)
        _send_email(
            email,
            "Verify your AutoWeave account",
            f"Welcome to AutoWeave.\n\nVerify your email:\n{link}\n\nThis link expires in {VERIFY_TTL_HOURS} hours.",
        )
    except Exception as e:
        # keep account created; user can resend
        print(f"EMAIL_SEND_FAILED(register): {repr(e)}")

    return {"ok": True, "message": "Registered. Verification email sent (if possible)."}


@router.post("/auth/login")
def login(data: LoginIn, db: Session = Depends(get_db)):
    email = data.email.lower().strip()
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()

    if (not user) or (not verify_password(data.password, user.password_hash)):
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Email not verified.")

    token = create_access_token({"sub": str(user.id), "email": user.email})
    return {"access_token": token, "token_type": "bearer"}


@router.post("/auth/resend-verify")
def resend_verify(data: ResendVerifyIn, db: Session = Depends(get_db)):
    email = data.email.lower().strip()
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()

    # Always return OK (avoid account enumeration)
    if not user or user.is_verified:
        return {"ok": True, "message": "If that email exists, a verification link has been sent."}

    raw_token = _new_token()
    user.verify_hash = _hash_token(raw_token)
    user.verify_expires_at = utcnow() + timedelta(hours=VERIFY_TTL_HOURS)
    user.updated_at = utcnow()
    db.commit()

    try:
        link = _verify_link(email, raw_token)
        _send_email(
            email,
            "Your AutoWeave verification link",
            f"Verify your email:\n{link}\n\nThis link expires in {VERIFY_TTL_HOURS} hours.",
        )
    except Exception as e:
        print(f"EMAIL_SEND_FAILED(resend_verify): {repr(e)}")

    return {"ok": True, "message": "If that email exists, a verification link has been sent."}


@router.post("/auth/verify")
def verify_email(data: VerifyIn, db: Session = Depends(get_db)):
    email = data.email.lower().strip()
    token = data.token.strip()

    now = utcnow()

    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid verification request.")

    vhash = user.verify_hash
    vexp = to_utc(user.verify_expires_at)

    if (not vhash) or (not vexp) or (vexp <= now):
        raise HTTPException(status_code=400, detail="Verification link expired. Please resend.")

    if _hash_token(token) != vhash:
        raise HTTPException(status_code=400, detail="Invalid verification token.")

    user.is_verified = True
    user.verify_hash = None
    user.verify_expires_at = None
    user.updated_at = utcnow()
    db.commit()

    return {"ok": True, "message": "Email verified."}


@router.post("/auth/forgot")
def forgot_password(data: ForgotIn, db: Session = Depends(get_db)):
    email = data.email.lower().strip()
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()

    # Always return OK (avoid account enumeration)
    if not user:
        return {"ok": True, "message": "If that email exists, a reset link has been sent."}

    raw_token = _new_token()
    token_hash = _hash_token(raw_token)
    expires_at = utcnow() + timedelta(hours=RESET_TTL_HOURS)

    reset = PasswordReset(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at,
        used_at=None,
        created_at=utcnow(),
    )
    db.add(reset)
    db.commit()

    try:
        link = _reset_link(email, raw_token)
        _send_email(
            email,
            "Reset your AutoWeave password",
            f"Reset your password:\n{link}\n\nThis link expires in {RESET_TTL_HOURS} hours.",
        )
    except Exception as e:
        print(f"EMAIL_SEND_FAILED(forgot): {repr(e)}")

    return {"ok": True, "message": "If that email exists, a reset link has been sent."}


@router.post("/auth/reset")
def reset_password(data: ResetIn, db: Session = Depends(get_db)):
    email = data.email.lower().strip()
    token = data.token.strip()
    now = utcnow()

    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid reset request.")

    token_hash = _hash_token(token)

    reset = (
        db.execute(
            select(PasswordReset)
            .where(PasswordReset.user_id == user.id)
            .where(PasswordReset.token_hash == token_hash)
            .order_by(PasswordReset.created_at.desc())
        )
        .scalars()
        .first()
    )

    if not reset:
        raise HTTPException(status_code=400, detail="Invalid reset token.")

    exp = to_utc(reset.expires_at)
    if reset.used_at or (not exp) or (exp <= now):
        raise HTTPException(status_code=400, detail="Reset link expired. Please request a new one.")

    user.password_hash = hash_password(data.new_password)
    user.updated_at = utcnow()

    reset.used_at = utcnow()
    db.commit()

    return {"ok": True, "message": "Password updated."}


@router.get("/auth/me")
def me(request: Request, db: Session = Depends(get_db)):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token.")
    token = auth.split(" ", 1)[1].strip()

    payload = decode_access_token(token)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token.")

    user = db.execute(select(User).where(User.id == int(user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token.")

    return {"id": user.id, "email": user.email, "is_verified": user.is_verified}
