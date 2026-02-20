import os
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from .db import get_db
from .models import OwUser
from .auth import create_access_token
from .mailer import send_email  # assumes you already have this

router = APIRouter()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

VERIFY_TTL_MINUTES = int(os.getenv("VERIFY_TTL_MINUTES", "60"))
RESET_TTL_MINUTES = int(os.getenv("RESET_TTL_MINUTES", "30"))

FRONTEND_URL = os.getenv("FRONTEND_URL", "").rstrip("/")
PUBLIC_APP_URL = os.getenv("PUBLIC_APP_URL", "").rstrip("/")  # optional
EMAIL_FROM = os.getenv("EMAIL_FROM", "")

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _normalize_aware(dt: datetime | None) -> datetime | None:
    """Ensure dt is timezone-aware (UTC) so comparisons never crash."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def _verify_link(email: str, token: str) -> str:
    base = FRONTEND_URL or PUBLIC_APP_URL
    if not base:
        # If you forgot to set FRONTEND_URL, still return something to debug
        return f"/tech.html?mode=verify&email={email}&token={token}"
    return f"{base}/tech.html?mode=verify&email={email}&token={token}"

def _reset_link(email: str, token: str) -> str:
    base = FRONTEND_URL or PUBLIC_APP_URL
    if not base:
        return f"/tech.html?mode=reset&email={email}&token={token}"
    return f"{base}/tech.html?mode=reset&email={email}&token={token}"

class Msg(BaseModel):
    message: str

class RegisterIn(BaseModel):
    email: EmailStr
    password: str

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

class EmailIn(BaseModel):
    email: EmailStr

class VerifyIn(BaseModel):
    email: EmailStr
    token: str

class ResetIn(BaseModel):
    email: EmailStr
    token: str
    new_password: str

@router.post("/auth/register", response_model=Msg)
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    pw = payload.password

    if len(pw) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")

    existing = db.query(OwUser).filter(OwUser.email == email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered.")

    now = utcnow()
    verify_token = secrets.token_urlsafe(32)
    verify_hash = _hash_token(verify_token)

    user = OwUser(
        email=email,
        password_hash=pwd_context.hash(pw),
        is_verified=False,
        verify_hash=verify_hash,
        verify_expires_at=now + timedelta(minutes=VERIFY_TTL_MINUTES),
        created_at=now,
        updated_at=now,
    )
    db.add(user)
    db.commit()

    # Send verify email (best-effort but don’t crash registration)
    try:
        link = _verify_link(email, verify_token)
        send_email(
            to_email=email,
            subject="Verify your AutoWeave account",
            html=f"<p>Click to verify:</p><p><a href='{link}'>{link}</a></p>",
        )
    except Exception as e:
        # keep register successful even if mail fails
        # (you can log e if you want)
        pass

    return {"message": "Registered. Please check your email to verify your account."}

@router.post("/auth/login", response_model=TokenOut)
def login(payload: LoginIn, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    user = db.query(OwUser).filter(OwUser.email == email).first()
    if not user or not pwd_context.verify(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Email not verified.")

    token = create_access_token(sub=email)
    return {"access_token": token}

@router.post("/auth/resend-verify", response_model=Msg)
def resend_verify(payload: EmailIn, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    user = db.query(OwUser).filter(OwUser.email == email).first()

    # Always return 200 to avoid account enumeration
    if not user or user.is_verified:
        return {"message": "If that email exists, a verification link has been sent."}

    now = utcnow()
    verify_token = secrets.token_urlsafe(32)
    user.verify_hash = _hash_token(verify_token)
    user.verify_expires_at = now + timedelta(minutes=VERIFY_TTL_MINUTES)
    user.updated_at = now
    db.commit()

    try:
        link = _verify_link(email, verify_token)
        send_email(
            to_email=email,
            subject="Your AutoWeave verification link",
            html=f"<p>Click to verify:</p><p><a href='{link}'>{link}</a></p>",
        )
    except Exception:
        # Don’t leak mail errors to client
        pass

    return {"message": "If that email exists, a verification link has been sent."}

@router.post("/auth/verify", response_model=Msg)
def verify_email(payload: VerifyIn, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    token_hash = _hash_token(payload.token)

    user = db.query(OwUser).filter(OwUser.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid verification request.")

    if user.is_verified:
        return {"message": "Email already verified."}

    vhash = user.verify_hash
    vexp = _normalize_aware(user.verify_expires_at)
    now = utcnow()

    if (not vhash) or (not vexp) or (vexp <= now):
        raise HTTPException(status_code=400, detail="Verification link expired. Please resend.")

    if vhash != token_hash:
        raise HTTPException(status_code=400, detail="Invalid verification token.")

    user.is_verified = True
    user.verify_hash = None
    user.verify_expires_at = None
    user.updated_at = now
    db.commit()

    return {"message": "Email verified successfully."}

@router.post("/auth/forgot", response_model=Msg)
def forgot_password(payload: EmailIn, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    user = db.query(OwUser).filter(OwUser.email == email).first()

    # Always 200 to avoid enumeration
    if not user:
        return {"message": "If that email exists, a reset link has been sent."}

    now = utcnow()
    reset_token = secrets.token_urlsafe(32)
    reset_hash = _hash_token(reset_token)

    # Reuse verify fields? Better to add reset fields in DB.
    # For now we store reset into verify_hash/expires only if you haven't made reset columns.
    # If you HAVE reset columns, tell me and I’ll align properly.
    user.verify_hash = reset_hash
    user.verify_expires_at = now + timedelta(minutes=RESET_TTL_MINUTES)
    user.updated_at = now
    db.commit()

    try:
        link = _reset_link(email, reset_token)
        send_email(
            to_email=email,
            subject="Reset your AutoWeave password",
            html=f"<p>Click to reset:</p><p><a href='{link}'>{link}</a></p>",
        )
    except Exception:
        pass

    return {"message": "If that email exists, a reset link has been sent."}

@router.post("/auth/reset", response_model=Msg)
def reset_password(payload: ResetIn, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    token_hash = _hash_token(payload.token)

    user = db.query(OwUser).filter(OwUser.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid reset request.")

    vhash = user.verify_hash
    vexp = _normalize_aware(user.verify_expires_at)
    now = utcnow()

    if (not vhash) or (not vexp) or (vexp <= now):
        raise HTTPException(status_code=400, detail="Reset link expired. Please request again.")

    if vhash != token_hash:
        raise HTTPException(status_code=400, detail="Invalid reset token.")

    if len(payload.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")

    user.password_hash = pwd_context.hash(payload.new_password)
    user.verify_hash = None
    user.verify_expires_at = None
    user.updated_at = now
    db.commit()

    return {"message": "Password reset successfully."}
