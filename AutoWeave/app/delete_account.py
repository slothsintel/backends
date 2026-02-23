from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import select

from .db import get_db
from .models import OwUser
from .auth import safe_decode_sub, verify_password

router = APIRouter()


def utcnow():
    return datetime.now(timezone.utc)


class DeleteAccountRequest(BaseModel):
    email: str
    password: str
    confirm: str


@router.post("/auth/delete-account")
def delete_account(payload: DeleteAccountRequest, request: Request, db: Session = Depends(get_db)):
    # 1) confirm text
    if (payload.confirm or "").strip().upper() != "DELETE":
        raise HTTPException(status_code=400, detail='Please type "DELETE" to confirm.')

    email = (payload.email or "").strip().lower()
    if not email or not payload.password:
        raise HTTPException(status_code=400, detail="Email and password are required.")

    # 2) find user
    user = db.execute(select(OwUser).where(OwUser.email == email)).scalar_one_or_none()
    if not user or user.is_deleted:
        raise HTTPException(status_code=404, detail="User not found.")

    # 3) verify password
    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    # 4) OPTIONAL safety: if a Bearer token is present, ensure it matches this user
    auth_header = request.headers.get("authorization") or ""
    token = auth_header.split(" ", 1)[1].strip() if auth_header.lower().startswith("bearer ") else ""
    if token:
        sub = safe_decode_sub(token)
        if sub and str(user.id) != str(sub):
            raise HTTPException(status_code=403, detail="Token/user mismatch.")

    # 5) soft delete
    user.is_deleted = True
    user.deleted_at = utcnow()
    user.updated_at = utcnow()

    db.add(user)
    db.commit()

    return {"ok": True}