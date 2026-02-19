from __future__ import annotations

import os
import secrets
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from sqlalchemy import select

from .services.merge import trim_aggregate_and_join
from .db import get_db
from .models import OwUser, OwPasswordReset
from .auth import hash_password, verify_password, create_access_token

router = APIRouter()

PUBLIC_APP_URL = (os.getenv("PUBLIC_APP_URL") or "https://autoweave.slothsintel.com").rstrip("/")
VERIFY_TTL_HOURS = int(os.getenv("VERIFY_TTL_HOURS", "48"))
RESET_TTL_HOURS = int(os.getenv("RESET_TTL_HOURS", "2"))


# -------------------------
# SMTP helper (AutoTrac style env vars)
# -------------------------

def send_email(to_email: str, subject: str, text_body: str) -> None:
    smtp_host = (os.getenv("SMTP_HOST") or "").strip()
    smtp_port = int(os.getenv("SMTP_PORT") or "587")
    smtp_user = (os.getenv("SMTP_USER") or "").strip()
    smtp_pass = (os.getenv("SMTP_PASS") or "").strip()

    email_from = (os.getenv("EMAIL_FROM") or smtp_user).strip()
    from_name = (os.getenv("EMAIL_FROM_NAME") or "Sloths Intel").strip()

    if not (smtp_host and smtp_user and smtp_pass and email_from):
        raise RuntimeError("SMTP env vars not fully set (SMTP_HOST/PORT/USER/PASS, EMAIL_FROM).")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"{from_name} <{email_from}>"
    msg["To"] = to_email
    msg.set_content(text_body)

    with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as s:
        s.ehlo()
        s.starttls()
        s.ehlo()
        s.login(smtp_user, smtp_pass)
        s.send_message(msg)


def _make_verify_link(email: str, token: str) -> str:
    # route back to your static tech workbench
    return f"{PUBLIC_APP_URL}/tech.html?mode=verify&email={email}&token={token}#workbench"


def _make_reset_link(email: str, token: str) -> str:
    return f"{PUBLIC_APP_URL}/tech.html?mode=reset&email={email}&token={token}#workbench"


def _user_has_inline_tokens(user: OwUser) -> bool:
    return all(hasattr(user, k) for k in ("verify_token_hash", "verify_expires_at", "reset_token_hash", "reset_expires_at"))


# -------------------------
# Schemas
# -------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ForgotRequest(BaseModel):
    email: EmailStr


class VerifyRequest(BaseModel):
    email: EmailStr
    token: str


class ResetRequest(BaseModel):
    email: EmailStr
    token: str
    new_password: str


# -------------------------
# Auth endpoints
# -------------------------

@router.post("/auth/register")
def register(data: RegisterRequest, db: Session = Depends(get_db)):
    email = data.email.strip().lower()
    password = data.password or ""

    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    existing = db.execute(select(OwUser).where(OwUser.email == email)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = OwUser(
        email=email,
        password_hash=hash_password(password),
        is_email_verified=False,
    )

    # generate verification token
    raw_verify = secrets.token_urlsafe(32)
    if _user_has_inline_tokens(user):
        user.verify_token_hash = hash_password(raw_verify)          # type: ignore[attr-defined]
        user.verify_expires_at = datetime.utcnow() + timedelta(hours=VERIFY_TTL_HOURS)  # type: ignore[attr-defined]

    db.add(user)
    db.commit()

    # send verification email (log failures instead of breaking registration)
    try:
        link = _make_verify_link(email, raw_verify)
        subject = "Confirm your AutoWeave account"
        body = (
            "Welcome to AutoWeave!\n\n"
            "Please confirm your email address:\n"
            f"{link}\n\n"
            f"This link expires in {VERIFY_TTL_HOURS} hours.\n\n"
            "If you didn’t create an account, ignore this email.\n\n"
            "— Sloths Intel\n"
        )
        send_email(email, subject, body)
    except Exception as e:
        print("EMAIL_SEND_FAILED(register):", repr(e))

    return {"ok": True}


@router.post("/auth/resend-verify")
def resend_verify(data: ForgotRequest, db: Session = Depends(get_db)):
    """
    Resend verification email. Always returns ok=True (no account enumeration).
    """
    email = data.email.strip().lower()

    user = db.execute(select(OwUser).where(OwUser.email == email)).scalar_one_or_none()
    if not user:
        return {"ok": True}

    if getattr(user, "is_email_verified", False):
        return {"ok": True}

    raw_verify = secrets.token_urlsafe(32)
    if _user_has_inline_tokens(user):
        user.verify_token_hash = hash_password(raw_verify)          # type: ignore[attr-defined]
        user.verify_expires_at = datetime.utcnow() + timedelta(hours=VERIFY_TTL_HOURS)  # type: ignore[attr-defined]
        db.commit()
    else:
        # If your model doesn't have inline token columns yet, you MUST add them;
        # otherwise you can't verify users via token.
        print("WARN: ow_users missing verify_* columns; cannot resend verify token.")
        return {"ok": True}

    try:
        link = _make_verify_link(email, raw_verify)
        subject = "Your AutoWeave verification link"
        body = (
            "Here is your AutoWeave verification link:\n\n"
            f"{link}\n\n"
            f"This link expires in {VERIFY_TTL_HOURS} hours.\n\n"
            "— Sloths Intel\n"
        )
        send_email(email, subject, body)
    except Exception as e:
        print("EMAIL_SEND_FAILED(resend_verify):", repr(e))

    return {"ok": True}


@router.post("/auth/verify")
def verify_email(data: VerifyRequest, db: Session = Depends(get_db)):
    email = data.email.strip().lower()
    token = (data.token or "").strip()
    now = datetime.utcnow()

    user = db.execute(select(OwUser).where(OwUser.email == email)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid verification token")

    if getattr(user, "is_email_verified", False):
        return {"ok": True}

    if not _user_has_inline_tokens(user):
        raise HTTPException(status_code=500, detail="Server missing verify token fields (run migration).")

    vhash = user.verify_token_hash  # type: ignore[attr-defined]
    vexp = user.verify_expires_at   # type: ignore[attr-defined]

    if (not vhash) or (not vexp) or (vexp <= now):
        raise HTTPException(status_code=400, detail="Invalid verification token")

    if not verify_password(token, vhash):
        raise HTTPException(status_code=400, detail="Invalid verification token")

    user.is_email_verified = True
    user.verify_token_hash = None  # type: ignore[attr-defined]
    user.verify_expires_at = None  # type: ignore[attr-defined]
    db.commit()

    return {"ok": True}


@router.post("/auth/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    email = data.email.strip().lower()
    password = data.password or ""

    user = db.execute(select(OwUser).where(OwUser.email == email)).scalar_one_or_none()
    if (not user) or (not verify_password(password, user.password_hash)):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not getattr(user, "is_email_verified", False):
        raise HTTPException(status_code=403, detail="Please verify your email before logging in")

    token = create_access_token(str(user.id))
    return {"access_token": token, "token_type": "bearer"}


@router.post("/auth/forgot")
def forgot(data: ForgotRequest, db: Session = Depends(get_db)):
    """
    Always ok=True. If user exists, creates reset token and emails link.
    """
    email = data.email.strip().lower()
    user = db.execute(select(OwUser).where(OwUser.email == email)).scalar_one_or_none()

    if user:
        raw_reset = secrets.token_urlsafe(32)
        expires = datetime.utcnow() + timedelta(hours=RESET_TTL_HOURS)

        if _user_has_inline_tokens(user):
            user.reset_token_hash = hash_password(raw_reset)  # type: ignore[attr-defined]
            user.reset_expires_at = expires                    # type: ignore[attr-defined]
            db.commit()
        else:
            # fallback table
            reset = OwPasswordReset(
                user_id=user.id,
                token_hash=hash_password(raw_reset),
                expires_at=expires,
            )
            db.add(reset)
            db.commit()

        try:
            link = _make_reset_link(email, raw_reset)
            subject = "Reset your AutoWeave password"
            body = (
                "We received a request to reset your AutoWeave password.\n\n"
                "Use this link to set a new password:\n"
                f"{link}\n\n"
                f"This link expires in {RESET_TTL_HOURS} hours.\n\n"
                "If you didn’t request this, ignore this email.\n\n"
                "— Sloths Intel\n"
            )
            send_email(email, subject, body)
        except Exception as e:
            print("EMAIL_SEND_FAILED(forgot):", repr(e))

    return {"ok": True}


@router.post("/auth/reset")
def reset_password(data: ResetRequest, db: Session = Depends(get_db)):
    email = data.email.strip().lower()
    token = (data.token or "").strip()
    new_password = data.new_password or ""
    now = datetime.utcnow()

    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    user = db.execute(select(OwUser).where(OwUser.email == email)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid reset token")

    # inline tokens preferred
    if _user_has_inline_tokens(user):
        rhash = user.reset_token_hash   # type: ignore[attr-defined]
        rexp = user.reset_expires_at    # type: ignore[attr-defined]
        if (not rhash) or (not rexp) or (rexp <= now):
            raise HTTPException(status_code=400, detail="Invalid reset token")
        if not verify_password(token, rhash):
            raise HTTPException(status_code=400, detail="Invalid reset token")

        user.password_hash = hash_password(new_password)
        user.reset_token_hash = None    # type: ignore[attr-defined]
        user.reset_expires_at = None    # type: ignore[attr-defined]
        db.commit()
        return {"ok": True}

    # fallback: ow_password_resets
    reset = db.execute(
        select(OwPasswordReset)
        .join(OwUser, OwPasswordReset.user_id == OwUser.id)
        .where(OwUser.email == email)
        .order_by(OwPasswordReset.created_at.desc())
    ).scalars().first()

    if (not reset) or reset.used_at or (reset.expires_at <= now):
        raise HTTPException(status_code=400, detail="Invalid reset token")

    if not verify_password(token, reset.token_hash):
        raise HTTPException(status_code=400, detail="Invalid reset token")

    user.password_hash = hash_password(new_password)
    reset.used_at = now
    db.commit()
    return {"ok": True}


# -------------------------
# Merge endpoint
# -------------------------

@router.post("/merge/autotrac")
async def merge_autotrac(
    time_entries_csv: UploadFile = File(...),
    incomes_csv: UploadFile = File(...),
    projects_csv: UploadFile | None = File(None),
):
    files = [time_entries_csv, incomes_csv] + ([projects_csv] if projects_csv else [])
    for f in files:
        if not f.filename.lower().endswith(".csv"):
            raise HTTPException(status_code=400, detail=f"Expected .csv file, got: {f.filename}")

    return await trim_aggregate_and_join(time_entries_csv, incomes_csv, projects_csv)
