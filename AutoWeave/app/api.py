# app/api.py
import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from .db import get_db
from .models import OwUser, OwPasswordReset
from .mailer import send_email
from .auth import create_access_token, safe_decode_sub

# NOTE:
# main.py includes this router with prefix="/api/v1"
# so keep router prefix="/auth" -> final: /api/v1/auth/...
router = APIRouter(prefix="/auth", tags=["auth"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


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
    # Use one of these in Render env vars:
    # FRONTEND_URL=https://autoweave.slothsintel.com
    return (os.getenv("FRONTEND_URL") or os.getenv("PUBLIC_APP_URL") or "").rstrip("/")


def build_verify_link(email: str, token: str) -> str:
    base = frontend_url()
    if not base:
        return ""
    return f"{base}/tech.html?mode=verify&email={email}&token={token}#workbench"


def build_reset_link(email: str, token: str) -> str:
    base = frontend_url()
    if not base:
        return ""
    return f"{base}/tech.html?mode=reset&email={email}&token={token}#workbench"


def send_verify_email(to_email: str, link: str, is_resend: bool = False) -> None:
    subject = "AutoWeave – Verify your email" + (" (resend)" if is_resend else "")
    text = (
        "Welcome to AutoWeave 👋\n\n"
        "Please verify your email by clicking the link below:\n\n"
        f"{link}\n\n"
        "This link will expire in 24 hours.\n\n"
        "If you did not create this account, you can ignore this email.\n\n"
        "— Sloths Intel Team"
    )
    send_email(to_email=to_email, subject=subject, text_body=text)


def send_reset_email(to_email: str, link: str) -> None:
    subject = "AutoWeave – Reset your password"
    text = (
        "Reset your password using the link below:\n\n"
        f"{link}\n\n"
        "This link will expire in 2 hours.\n\n"
        "If you did not request this reset, ignore this email.\n\n"
        "— Sloths Intel Team"
    )
    send_email(to_email=to_email, subject=subject, text_body=text)


def send_welcome_email(to_email: str) -> None:
    subject = "Welcome to AutoWeave 👋"
    text = (
        "Welcome to AutoWeave!\n\n"
        "You can now sign in and start weaving your CSVs into clean, reliable outputs.\n\n"
        "If you ever need help, just reply to this email.\n\n"
        "— Sloths Intel Team"
    )
    send_email(to_email=to_email, subject=subject, text_body=text)


# ------------------------
# Schemas
# ------------------------
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class VerifyRequest(BaseModel):
    email: EmailStr
    token: str


class EmailOnly(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    token: str
    new_password: str


class DeleteAccountRequest(BaseModel):
    password: str
    confirm: str


# ------------------------
# Password hashing (NO bcrypt)
# ------------------------
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def hash_password(pw: str) -> str:
    return pwd_context.hash(pw)


def verify_password(pw: str, pw_hash: str) -> bool:
    return pwd_context.verify(pw, pw_hash)


# ------------------------
# Endpoints
# ------------------------
@router.post("/register")
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
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
        created_at=utcnow(),
        updated_at=utcnow(),
    )

    token = new_token_urlsafe()
    user.verify_hash = sha256_hex(token)
    user.verify_expires_at = utcnow() + timedelta(hours=24)

    db.add(user)
    db.commit()

    link = build_verify_link(user.email, token)
    if link:
        send_verify_email(user.email, link, is_resend=False)

    return {"ok": True}


@router.post("/resend-verify")
def resend_verify(payload: EmailOnly, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    user = db.query(OwUser).filter(OwUser.email == email).first()

    # Always 200 (don’t leak existence)
    if not user:
        return {"ok": True}
    if getattr(user, "is_deleted", False):
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
        send_verify_email(user.email, link, is_resend=True)

    return {"ok": True}


@router.post("/verify")
def verify_email(payload: VerifyRequest, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    token_hash = sha256_hex(payload.token.strip())

    user = db.query(OwUser).filter(OwUser.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid verification link")

    if getattr(user, "is_deleted", False):
        raise HTTPException(status_code=400, detail="Invalid verification link")

    if user.is_verified:
        # Idempotent success
        return {"ok": True}

    if not user.verify_hash or user.verify_hash != token_hash:
        raise HTTPException(status_code=400, detail="Invalid verification link")

    if not user.verify_expires_at or user.verify_expires_at < utcnow():
        raise HTTPException(status_code=400, detail="Verification link expired")

    user.is_verified = True
    user.verify_hash = None
    user.verify_expires_at = None
    user.updated_at = utcnow()

    # Optional: welcome email + "welcome_sent" bookkeeping (only if you add these columns in your model later)
    should_send_welcome = True
    if hasattr(OwUser, "welcome_sent"):
        # if model/column exists, only send once
        try:
            if getattr(user, "welcome_sent", False):
                should_send_welcome = False
        except Exception:
            pass

    if should_send_welcome:
        try:
            send_welcome_email(user.email)
            if hasattr(OwUser, "welcome_sent"):
                setattr(user, "welcome_sent", True)
            if hasattr(OwUser, "welcome_sent_at"):
                setattr(user, "welcome_sent_at", utcnow())
        except Exception:
            # do not fail verify because email sending failed
            pass

    db.add(user)
    db.commit()

    return {"ok": True}


@router.post("/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    pw = payload.password

    user = db.query(OwUser).filter(OwUser.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if getattr(user, "is_deleted", False):
        raise HTTPException(status_code=401, detail="Account is deleted")

    if not verify_password(pw, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.is_verified:
        raise HTTPException(status_code=401, detail="Email not verified")

    token = create_access_token(str(user.id))  # sub = user.id (stringified)
    user.updated_at = utcnow()
    db.add(user)
    db.commit()

    return {"access_token": token, "token_type": "bearer"}


@router.post("/forgot")
def forgot_password(payload: EmailOnly, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    user = db.query(OwUser).filter(OwUser.email == email).first()

    # Always 200
    if not user:
        return {"ok": True}
    if getattr(user, "is_deleted", False):
        return {"ok": True}

    token = new_token_urlsafe()
    token_hash = sha256_hex(token)

    user.reset_hash = token_hash
    user.reset_expires_at = utcnow() + timedelta(hours=2)
    user.updated_at = utcnow()
    db.add(user)

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
        send_reset_email(user.email, link)

    return {"ok": True}


@router.post("/reset")
def reset_password(payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    token_hash = sha256_hex(payload.token.strip())
    new_pw = payload.new_password

    if len(new_pw) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    user = db.query(OwUser).filter(OwUser.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid reset link")

    if getattr(user, "is_deleted", False):
        raise HTTPException(status_code=400, detail="Invalid reset link")

    if not user.reset_hash or user.reset_hash != token_hash:
        raise HTTPException(status_code=400, detail="Invalid reset link")

    if not user.reset_expires_at or user.reset_expires_at < utcnow():
        raise HTTPException(status_code=400, detail="Reset link expired")

    # Mark password reset token row (best effort)
    pr = (
        db.query(OwPasswordReset)
        .filter(OwPasswordReset.user_id == user.id, OwPasswordReset.token_hash == token_hash)
        .first()
    )
    if pr and pr.used_at is None:
        pr.used_at = utcnow()
        db.add(pr)

    user.password_hash = hash_password(new_pw)
    user.reset_hash = None
    user.reset_expires_at = None
    user.updated_at = utcnow()
    db.add(user)
    db.commit()

    return {"ok": True}


@router.post("/delete-account")
def delete_account(
    payload: DeleteAccountRequest,
    request: Request,
    token: str | None = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    """
    Accept BOTH styles of JWT:
    - newer: sub = user.id (int-ish)
    - older: sub = email (string)
    """
    auth = request.headers.get("authorization", "")
    if not token:
        if auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()

    if not token:
        raise HTTPException(status_code=401, detail="Missing token")

    print("DELETE-ACCOUNT auth header present =", bool(auth))
    print("DELETE-ACCOUNT token length =", len(token or ""))

    sub = safe_decode_sub(token)
    if not sub:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = None

    # Try new-style token: sub=user.id
    try:
        user_id = int(str(sub))
        user = db.query(OwUser).filter(OwUser.id == user_id).first()
    except Exception:
        user = None

    # Fallback old-style token: sub=email
    if user is None:
        email = str(sub).lower().strip()
        user = db.query(OwUser).filter(OwUser.email == email).first()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")

    if payload.confirm.strip().upper() != "DELETE":
        raise HTTPException(status_code=400, detail='Type "DELETE" to confirm')

    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid password")

    # Soft-delete if your MODEL has these columns (add them later if you want).
    if hasattr(OwUser, "is_deleted"):
        setattr(user, "is_deleted", True)
        if hasattr(OwUser, "deleted_at"):
            setattr(user, "deleted_at", utcnow())
        user.updated_at = utcnow()
        db.add(user)
        db.commit()
    else:
        # Hard delete (current models.py does not have soft-delete fields)
        db.delete(user)
        db.commit()

    return {"ok": True}