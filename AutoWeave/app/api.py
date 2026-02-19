import os
import secrets
from datetime import datetime, timedelta

from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from sqlalchemy import select

from .services.merge import trim_aggregate_and_join
from .db import SessionLocal
from .models import OwUser
from .auth import hash_password, verify_password, create_access_token
from .mailer import send_email

router = APIRouter()

PUBLIC_APP_URL = (os.getenv("PUBLIC_APP_URL") or os.getenv("PUBLIC_BASE_URL") or "https://autoweave.slothsintel.com").rstrip("/")
VERIFY_TTL_HOURS = int(os.getenv("VERIFY_TTL_HOURS", "48"))
RESET_TTL_HOURS = int(os.getenv("RESET_TTL_HOURS", "2"))


# -------------------------
# DB dependency
# -------------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# -------------------------
# Auth schemas
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
# Auth endpoints (AutoTrac-style)
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

    # Create verify token (stored on user)
    raw_verify = secrets.token_urlsafe(32)
    user.verify_token_hash = hash_password(raw_verify)
    user.verify_expires_at = datetime.utcnow() + timedelta(hours=VERIFY_TTL_HOURS)

    db.add(user)
    db.commit()

    # Send verification email (do not fail registration if email fails)
    try:
        verify_link = f"{PUBLIC_APP_URL}/verify?token={raw_verify}&email={email}"
        subject = "Confirm your AutoWeave account"
        body = (
            "Welcome to AutoWeave!\n\n"
            "Please confirm your email address to activate your account:\n"
            f"{verify_link}\n\n"
            f"This link expires in {VERIFY_TTL_HOURS} hours.\n\n"
            "If you didn’t create an account, you can ignore this email.\n\n"
            "— Sloths Intel\n"
            "info@slothsintel.com\n"
        )
        send_email(email, subject, body)
    except Exception:
        # Keep it non-blocking like many SaaS apps
        pass

    return {"ok": True}


@router.post("/auth/verify")
def verify_email(data: VerifyRequest, db: Session = Depends(get_db)):
    email = data.email.strip().lower()
    token = (data.token or "").strip()
    now = datetime.utcnow()

    user = db.execute(select(OwUser).where(OwUser.email == email)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid verification token")

    # Idempotent: already verified -> ok
    if user.is_email_verified:
        return {"ok": True}

    if not user.verify_token_hash or not user.verify_expires_at or user.verify_expires_at <= now:
        raise HTTPException(status_code=400, detail="Invalid verification token")

    if not verify_password(token, user.verify_token_hash):
        raise HTTPException(status_code=400, detail="Invalid verification token")

    user.is_email_verified = True
    user.verify_token_hash = None
    user.verify_expires_at = None
    db.commit()

    return {"ok": True}


@router.post("/auth/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    email = data.email.strip().lower()
    password = data.password or ""

    user = db.execute(select(OwUser).where(OwUser.email == email)).scalar_one_or_none()
    if (not user) or (not verify_password(password, user.password_hash)):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # AutoTrac-style: require verification
    if not user.is_email_verified:
        raise HTTPException(status_code=403, detail="Please verify your email before logging in")

    token = create_access_token(str(user.id))
    return {"access_token": token, "token_type": "bearer"}


@router.post("/auth/forgot")
def forgot(data: ForgotRequest, db: Session = Depends(get_db)):
    """
    Always returns ok=True to avoid leaking whether an email exists.
    If the user exists, sets reset token on the user and emails a reset link.
    """
    email = data.email.strip().lower()

    user = db.execute(select(OwUser).where(OwUser.email == email)).scalar_one_or_none()

    if user:
        raw_reset = secrets.token_urlsafe(32)
        user.reset_token_hash = hash_password(raw_reset)
        user.reset_expires_at = datetime.utcnow() + timedelta(hours=RESET_TTL_HOURS)
        db.commit()

        try:
            reset_link = f"{PUBLIC_APP_URL}/reset-password?token={raw_reset}&email={email}"
            subject = "Reset your AutoWeave password"
            body = (
                "We received a request to reset your AutoWeave password.\n\n"
                "Use this link to set a new password:\n"
                f"{reset_link}\n\n"
                f"This link expires in {RESET_TTL_HOURS} hours.\n\n"
                "If you didn’t request this, you can ignore this email.\n\n"
                "— Sloths Intel\n"
                "info@slothsintel.com\n"
            )
            send_email(email, subject, body)
        except Exception:
            pass

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

    if not user.reset_token_hash or not user.reset_expires_at or user.reset_expires_at <= now:
        raise HTTPException(status_code=400, detail="Invalid reset token")

    if not verify_password(token, user.reset_token_hash):
        raise HTTPException(status_code=400, detail="Invalid reset token")

    user.password_hash = hash_password(new_password)
    user.reset_token_hash = None
    user.reset_expires_at = None
    db.commit()

    return {"ok": True}


# -------------------------
# Existing merge endpoint
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
