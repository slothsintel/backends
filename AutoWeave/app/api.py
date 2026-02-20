# app/api.py
import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from passlib.context import CryptContext

from .db import get_db
from .models import OwUser, OwPasswordReset
from .mailer import send_email
from .auth import create_access_token, safe_decode_sub

from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError

from .auth import safe_decode_sub  # your helper that returns sub or None
from .passwords import verify_password

# main.py mounts this router at prefix="/api/v1"
# final URLs: /api/v1/auth/...
router = APIRouter(prefix="/auth", tags=["auth"])
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
    # prefer your explicit FRONTEND_URL; fallback to PUBLIC_APP_URL
    return (os.getenv("FRONTEND_URL") or os.getenv("PUBLIC_APP_URL") or "").rstrip("/")


def _require_bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    return authorization.split(" ", 1)[1].strip()


def _require_current_user(db: Session, authorization: str | None) -> OwUser:
    token = _require_bearer_token(authorization)
    sub = safe_decode_sub(token)
    if not sub:
        raise HTTPException(status_code=401, detail="Invalid token")

    try:
        user_id = int(sub)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(OwUser).filter(OwUser.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")

    # If you later add soft-delete fields to the model, this will work automatically
    if getattr(user, "is_deleted", False):
        raise HTTPException(status_code=403, detail="Account deleted")

    return user


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


class DeleteAccountRequest(BaseModel):
    password: str
    confirm: str  # must be "DELETE"


# ------------------------
# Password hashing (PBKDF2 avoids bcrypt 72-byte limit + bcrypt backend issues)
# ------------------------
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


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
    return f"{base}/tech.html?mode=verify&email={email}&token={token}#workbench"


def build_reset_link(email: str, token: str) -> str:
    base = frontend_url()
    if not base:
        return ""
    return f"{base}/tech.html?mode=reset&email={email}&token={token}#workbench"


# ------------------------
# Email content
# ------------------------
def send_welcome_email(to_email: str):
    base = frontend_url()
    start_link = f"{base}/tech.html#guided" if base else ""

    body = f"""
Welcome to AutoWeave 🎉

Your email is verified and your account is ready.

What you can do next:
1) Upload your CSVs (projects / income / time entries) securely from the dashboard
2) Run merge
3) Preview stats + charts
4) Export a clean dataset

{("Start here: " + start_link) if start_link else ""}

If you need help, just reply to this email.

— Sloths Intel
""".strip()

    send_email(
        to_email=to_email,
        subject="AutoWeave – Welcome aboard",
        text_body=body,
    )


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
            subject="AutoWeave – Verify Your Email",
            text_body=f"""
Welcome to AutoWeave 👋

Please verify your email by clicking the link below:

{link}

This link will expire in 24 hours.

If you did not create this account, you can safely ignore this email.

— Sloths Intel Team
""".strip(),
        )

    return {"ok": True}


@router.post("/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    user = db.query(OwUser).filter(OwUser.email == email).first()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if getattr(user, "is_deleted", False):
        raise HTTPException(status_code=403, detail="Account deleted")

    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Please verify your email before logging in")

    token = create_access_token(str(user.id))
    return {"access_token": token, "token_type": "bearer"}


@router.post("/resend-verify")
def resend_verify(payload: EmailOnly, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    user = db.query(OwUser).filter(OwUser.email == email).first()

    # Always 200 (don’t leak whether user exists)
    if not user or getattr(user, "is_deleted", False) or user.is_verified:
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
            subject="AutoWeave – Verify Your Email",
            text_body=f"""
Welcome back 👋

Please verify your email by clicking the link below:

{link}

This link will expire in 24 hours.

If you did not request this email, you can safely ignore it.

— Sloths Intel Team
""".strip(),
        )

    return {"ok": True}


@router.post("/verify")
def verify_email(payload: VerifyRequest, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    token = payload.token.strip()
    token_hash = sha256_hex(token)
    now = utcnow()

    user = db.query(OwUser).filter(OwUser.email == email).first()
    if not user or getattr(user, "is_deleted", False):
        raise HTTPException(status_code=400, detail="Invalid token")

    # If already verified, do not re-send welcome
    if user.is_verified:
        return {"ok": True}

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

    # Send welcome email after successful verification (SMTP failure won't block verify)
    try:
        send_welcome_email(user.email)
    except Exception:
        pass

    return {"ok": True}


@router.post("/forgot")
def forgot_password(payload: ForgotRequest, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    user = db.query(OwUser).filter(OwUser.email == email).first()

    # Always 200 (don’t leak)
    if not user or getattr(user, "is_deleted", False):
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
            subject="AutoWeave – Password Reset",
            text_body=f"""
We received a request to reset your AutoWeave password.

Click the link below to set a new password:

{link}

This link will expire in 2 hours.

If you did not request this, please ignore this email.

— Sloths Intel Team
""".strip(),
        )

    return {"ok": True}


@router.post("/reset")
def reset_password(payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    token = payload.token.strip()
    now = utcnow()

    user = db.query(OwUser).filter(OwUser.email == email).first()
    if not user or getattr(user, "is_deleted", False):
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


@router.post("/auth/delete-account")
def delete_account(
    payload: DeleteAccountRequest,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    sub = safe_decode_sub(token)
    if not sub:
        raise HTTPException(status_code=401, detail="Invalid token")

    # ✅ IMPORTANT: sub is user.id (string), so query by id
    user = db.query(OwUser).filter(OwUser.id == int(sub)).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")

    if payload.confirm.upper() != "DELETE":
        raise HTTPException(status_code=400, detail='Type "DELETE" to confirm')

    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid password")

    # soft delete
    user.is_deleted = True
    user.deleted_at = utcnow()
    db.add(user)
    db.commit()

    return {"ok": True}