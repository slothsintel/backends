# app/api.py
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from .db import get_db
from .models import OwUser
from .mailer import send_email

router = APIRouter()

# -----------------------------------------------------------------------------
# Security / JWT
# -----------------------------------------------------------------------------
SECRET_KEY = os.getenv("JWT_SECRET", os.getenv("SECRET_KEY", "change-me"))
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "10080"))  # 7 days default

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def utcnow() -> datetime:
    return datetime.utcnow()


def hash_password(p: str) -> str:
    return pwd_context.hash(p)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(plain, hashed)
    except Exception:
        return False


def _clean_token(token: str) -> str:
    """
    Defend against frontend accidentally storing 'Bearer <jwt>' and then sending
    'Authorization: Bearer Bearer <jwt>'.
    """
    if not token:
        return token
    t = token.strip()
    # strip repeated "Bearer " prefixes if present
    for _ in range(3):
        if t.lower().startswith("bearer "):
            t = t[7:].strip()
        else:
            break
    return t


def create_access_token(sub: str) -> str:
    expire = utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": sub, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def safe_decode_sub(token: str) -> Optional[str]:
    token = _clean_token(token)
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None


def _ow_users_has_column(db: Session, colname: str) -> bool:
    try:
        insp = inspect(db.get_bind())
        cols = {c["name"] for c in insp.get_columns("ow_users")}
        return colname in cols
    except Exception:
        return False


def _is_user_deleted(db: Session, user_id: int) -> bool:
    if not _ow_users_has_column(db, "is_deleted"):
        return False
    row = db.execute(
        text("SELECT is_deleted FROM ow_users WHERE id = :id"),
        {"id": user_id},
    ).fetchone()
    return bool(row[0]) if row else False


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> OwUser:
    sub = safe_decode_sub(token)
    if not sub:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Accept both sub=email and sub=id
    user: Optional[OwUser] = None
    if sub.isdigit():
        user = db.query(OwUser).filter(OwUser.id == int(sub)).first()
    if user is None:
        user = db.query(OwUser).filter(OwUser.email == sub.lower()).first()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")

    if _is_user_deleted(db, user.id):
        raise HTTPException(status_code=401, detail="Invalid token")

    return user


# -----------------------------------------------------------------------------
# Schemas
# -----------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class ResendVerifyRequest(BaseModel):
    email: str


class ForgotRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


class DeleteAccountRequest(BaseModel):
    password: str
    confirm: str


# -----------------------------------------------------------------------------
# Email helpers
# -----------------------------------------------------------------------------
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "https://autoweave.slothsintel.com")


def _send_verify_email(to_email: str, raw_token: str) -> None:
    verify_link = f"{FRONTEND_BASE_URL}/tech.html?verify={raw_token}"
    subject = "Verify your AutoWeave account"
    html = f"""
    <p>Hi,</p>
    <p>Please verify your AutoWeave account by clicking the link below:</p>
    <p><a href="{verify_link}">Verify my account</a></p>
    <p>This link expires in 30 minutes.</p>
    """
    send_email(to_email, subject, html)


def _send_reset_email(to_email: str, raw_token: str) -> None:
    reset_link = f"{FRONTEND_BASE_URL}/tech.html?reset={raw_token}"
    subject = "Reset your AutoWeave password"
    html = f"""
    <p>Hi,</p>
    <p>Click the link below to reset your password:</p>
    <p><a href="{reset_link}">Reset my password</a></p>
    <p>This link expires in 30 minutes.</p>
    """
    send_email(to_email, subject, html)


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@router.get("/health")
def health():
    return {"ok": True}


@router.post("/auth/register")
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    password = payload.password

    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email")

    if not password or len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    existing = db.query(OwUser).filter(OwUser.email == email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    verify_token = secrets.token_urlsafe(32)
    user = OwUser(
        email=email,
        password_hash=hash_password(password),
        is_verified=False,
        verify_hash=hash_password(verify_token),
        verify_expires_at=utcnow() + timedelta(minutes=30),
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    db.add(user)
    db.commit()

    # Best-effort email send (don’t block registration if email fails)
    try:
        _send_verify_email(email, verify_token)
    except Exception:
        pass

    return {"ok": True}


@router.get("/auth/verify")
def verify_email(token: str = Query(...), db: Session = Depends(get_db)):
    raw = token.strip()
    if not raw:
        raise HTTPException(status_code=400, detail="Missing token")

    # Find a not-yet-verified user whose verify_hash matches
    # (bcrypt hashes can’t be searched directly, so we scan only unverified rows)
    candidates = db.query(OwUser).filter(OwUser.is_verified == False).all()  # noqa: E712
    now = utcnow()

    for user in candidates:
        if user.verify_expires_at and user.verify_expires_at < now:
            continue
        if user.verify_hash and verify_password(raw, user.verify_hash):
            user.is_verified = True
            user.verify_hash = None
            user.verify_expires_at = None
            user.updated_at = now
            db.add(user)
            db.commit()

            # Optional welcome letter (only if columns exist)
            if _ow_users_has_column(db, "welcome_sent"):
                try:
                    db.execute(
                        text(
                            "UPDATE ow_users SET welcome_sent=true, welcome_sent_at=NOW(), updated_at=NOW() "
                            "WHERE id=:id AND (welcome_sent IS NULL OR welcome_sent=false)"
                        ),
                        {"id": user.id},
                    )
                    db.commit()
                except Exception:
                    pass

            try:
                send_email(
                    user.email,
                    "Welcome to AutoWeave",
                    "<p>Welcome aboard! Your account is verified and ready to use.</p>",
                )
            except Exception:
                pass

            return {"ok": True}

    raise HTTPException(status_code=400, detail="Invalid or expired token")


@router.post("/auth/resend-verify")
def resend_verify(payload: ResendVerifyRequest, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    user = db.query(OwUser).filter(OwUser.email == email).first()

    # Always return ok (don’t leak which emails exist)
    if not user or user.is_verified:
        return {"ok": True}

    verify_token = secrets.token_urlsafe(32)
    user.verify_hash = hash_password(verify_token)
    user.verify_expires_at = utcnow() + timedelta(minutes=30)
    user.updated_at = utcnow()
    db.add(user)
    db.commit()

    try:
        _send_verify_email(email, verify_token)
    except Exception:
        pass

    return {"ok": True}


@router.post("/auth/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    user = db.query(OwUser).filter(OwUser.email == email).first()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if _is_user_deleted(db, user.id):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.is_verified:
        raise HTTPException(status_code=401, detail="Email not verified")

    token = create_access_token(str(user.id))  # sub=user.id
    return {"access_token": token, "token_type": "bearer", "user": {"id": user.id, "email": user.email}}


@router.post("/auth/forgot")
def forgot_password(payload: ForgotRequest, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    user = db.query(OwUser).filter(OwUser.email == email).first()

    # Always return ok (don’t leak which emails exist)
    if not user or _is_user_deleted(db, user.id):
        return {"ok": True}

    raw_token = secrets.token_urlsafe(32)
    user.reset_hash = hash_password(raw_token)
    user.reset_expires_at = utcnow() + timedelta(minutes=30)
    user.updated_at = utcnow()
    db.add(user)
    db.commit()

    try:
        _send_reset_email(email, raw_token)
    except Exception:
        pass

    return {"ok": True}


@router.post("/auth/reset")
def reset_password(payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    raw = payload.token.strip()
    new_pw = payload.new_password

    if not raw:
        raise HTTPException(status_code=400, detail="Missing token")
    if not new_pw or len(new_pw) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    now = utcnow()
    # Scan only users with a reset_hash set (bcrypt not searchable)
    candidates = db.query(OwUser).filter(OwUser.reset_hash.isnot(None)).all()
    for user in candidates:
        if user.reset_expires_at and user.reset_expires_at < now:
            continue
        if user.reset_hash and verify_password(raw, user.reset_hash):
            user.password_hash = hash_password(new_pw)
            user.reset_hash = None
            user.reset_expires_at = None
            user.updated_at = now
            db.add(user)
            db.commit()
            return {"ok": True}

    raise HTTPException(status_code=400, detail="Invalid or expired token")


@router.get("/auth/me")
def me(user: OwUser = Depends(get_current_user)):
    return {"id": user.id, "email": user.email}


@router.post("/auth/delete-account")
def delete_account(
    payload: DeleteAccountRequest,
    user: OwUser = Depends(get_current_user),
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    """
    Self-serve delete.
    - Requires valid Authorization: Bearer <jwt>
    - Requires password + confirm="DELETE"
    - Soft-delete if ow_users has is_deleted/deleted_at, otherwise hard delete.
    """
    # Extra defense: if the frontend ever sends "Bearer Bearer <jwt>", oauth2_scheme returns "Bearer <jwt>"
    # and get_current_user would already have failed. But keep this to be safe:
    sub = safe_decode_sub(token)
    if not sub:
        raise HTTPException(status_code=401, detail="Invalid token")

    if payload.confirm.strip().upper() != "DELETE":
        raise HTTPException(status_code=400, detail='Type "DELETE" to confirm')

    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid password")

    now = utcnow()
    if _ow_users_has_column(db, "is_deleted"):
        # Soft delete via raw SQL so it works even if your SQLAlchemy model
        # doesn’t have these columns yet.
        sets = ["is_deleted=true", "updated_at=NOW()"]
        if _ow_users_has_column(db, "deleted_at"):
            sets.append("deleted_at=NOW()")
        db.execute(
            text(f"UPDATE ow_users SET {', '.join(sets)} WHERE id=:id"),
            {"id": user.id},
        )
        db.commit()
    else:
        db.delete(user)
        db.commit()

    return {"ok": True}