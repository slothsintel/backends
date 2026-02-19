from datetime import datetime, timedelta
import secrets

from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from sqlalchemy import select

from .services.merge import trim_aggregate_and_join
from .db import get_db
from .models import OwUser, OwPasswordReset
from .auth import hash_password, verify_password, create_access_token

router = APIRouter()


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


# -------------------------
# Auth endpoints
# -------------------------

@router.post("/auth/register")
def register(data: RegisterRequest, db: Session = Depends(get_db)):
    email = data.email.strip().lower()
    password = data.password or ""

    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    existing = db.execute(
        select(OwUser).where(OwUser.email == email)
    ).scalar_one_or_none()

    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = OwUser(
        email=email,
        password_hash=hash_password(password),
        is_email_verified=False,
    )
    db.add(user)
    db.commit()

    # TODO (later): send welcome email + verification link
    return {"ok": True}


@router.post("/auth/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    email = data.email.strip().lower()
    password = data.password or ""

    user = db.execute(
        select(OwUser).where(OwUser.email == email)
    ).scalar_one_or_none()

    if (not user) or (not verify_password(password, user.password_hash)):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Optional (later): enforce email verification
    # if not user.is_email_verified:
    #     raise HTTPException(status_code=403, detail="Please verify your email before logging in")

    token = create_access_token(str(user.id))
    return {"access_token": token, "token_type": "bearer"}


@router.post("/auth/forgot")
def forgot(data: ForgotRequest, db: Session = Depends(get_db)):
    """
    Always returns ok=True to avoid leaking whether an email exists.
    Creates a reset token record if the user exists.
    """
    email = data.email.strip().lower()

    user = db.execute(
        select(OwUser).where(OwUser.email == email)
    ).scalar_one_or_none()

    if user:
        raw_token = secrets.token_urlsafe(32)

        reset = OwPasswordReset(
            user_id=user.id,
            token_hash=hash_password(raw_token),
            expires_at=datetime.utcnow() + timedelta(minutes=30),
            used_at=None,
        )
        db.add(reset)
        db.commit()

        # TODO (later): email user a reset link containing raw_token
        # e.g. https://autoweave.slothsintel.com/reset?token=...&email=...

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
