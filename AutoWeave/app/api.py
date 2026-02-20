# app/api.py
import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from passlib.context import CryptContext

from .db import get_db
from .models import OwUser, OwPasswordReset
from .mailer import send_email
from .auth import create_access_token, safe_decode_sub

# If main.py DOES NOT add a /api/v1 prefix, keep this:
router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
# If main.py ALREADY mounts /api/v1, use instead:
# router = APIRouter(prefix="/auth", tags=["auth"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


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


class ForgotRequest(BaseModel):
    email: EmailStr


class ResendVerifyRequest(BaseModel):
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
        # Your mailer.py likely expects text_body (NOT text)
        send_email(
            to_email=user.email,
            subject="AutoWeave – Verify your email",
            text_body=(
                "Welcome to AutoWeave 👋\n\n"
                "Please verify your email by clicking the link below:\n\n"
                f"{link}\n\n"
                "This link will expire in 24 hours.\n\n"
                "If you did not create this account, you can ignore this email.\n\n"
                "— Sloths Intel"
            ),
        )

    return {"ok": True}


@router.post("/resend-verify")
def resend_verify(payload: ResendVerifyRequest, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    user = db.query(OwUser).filter(OwUser.email == email).first()

    # Always 200 (don’t leak existence)
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
            subject="AutoWeave – Verify your email (resend)",
            text_body=(
                "Here is your new verification link:\n\n"
                f"{link}\n\n"
                "This link will expire in 24 hours.\n\n"
                "— Sloths Intel"
            ),
        )

    return {"ok": True}


@router.post("/verify")
def verify_email(payload: VerifyRequest, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    token = payload.token.strip()
    token_hash = sha256_hex(token)
    now = utcnow()

    user = db.query(OwUser).filter(OwUser.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    if (not user.verify_hash) or (not user.verify_expires_at):
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    if user.verify_expires_at <= now or user.verify_hash != token_hash:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    user.is_verified = True
    user.verify_hash = None
    user.verify_expires_at = None
    user.updated_at = now
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

    # IMPORTANT: sub is user.id (string)
    token = create_access_token(str(user.id))

    user.updated_at = utcnow()
    db.add(user)
    db.commit()

    return {"access_token": token, "token_type": "bearer"}


@router.post("/forgot")
def forgot_password(payload: ForgotRequest, db: Session = Depends(get_db)):
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
            subject="AutoWeave – Reset your password",
            text_body=(
                "Reset your password using the link below:\n\n"
                f"{link}\n\n"
                "This link will expire in 2 hours.\n\n"
                "If you did not request this reset, ignore this email.\n\n"
                "— Sloths Intel"
            ),
        )

    return {"ok": True}


@router.post("/reset")
def reset_password(payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    token = payload.token.strip()
    new_pw = payload.new_password

    if len(new_pw) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    user = db.query(OwUser).filter(OwUser.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    if getattr(user, "is_deleted", False):
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    now = utcnow()
    token_hash = sha256_hex(token)

    if (not user.reset_hash) or (not user.reset_expires_at):
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    if user.reset_expires_at <= now or user.reset_hash != token_hash:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    user.password_hash = hash_password(new_pw)
    user.reset_hash = None
    user.reset_expires_at = None
    user.updated_at = now
    db.add(user)
    db.commit()

    return {"ok": True}


@router.post("/delete-account")
def delete_account(
    payload: DeleteAccountRequest,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    """
    Soft-delete current user.
    FIX: JWT sub is user.id, so we must query by id.
    """
    sub = safe_decode_sub(token)
    if not sub:
        raise HTTPException(status_code=401, detail="Invalid token")

    # If your OwUser.id is UUID, remove int() and query by string.
    try:
        user_id = int(sub)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(OwUser).filter(OwUser.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")

    if payload.confirm.strip().upper() != "DELETE":
        raise HTTPException(status_code=400, detail='Type "DELETE" to confirm')

    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid password")

    # soft delete if fields exist, else hard delete
    if hasattr(user, "is_deleted"):
        user.is_deleted = True
        if hasattr(user, "deleted_at"):
            user.deleted_at = utcnow()
        user.updated_at = utcnow()
        db.add(user)
        db.commit()
    else:
        db.delete(user)
        db.commit()

    return {"ok": True}