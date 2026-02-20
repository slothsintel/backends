from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Union

import jwt
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(
    subject_or_payload: Union[int, str, Dict[str, Any]],
    secret: Optional[str] = None,
    expires_minutes: int = 60 * 24,
) -> str:
    """
    Backward compatible:

    - Old usage: create_access_token(user_id)
    - New usage: create_access_token({"sub": "123"}, secret, minutes)
    """
    if secret is None:
        secret = os.getenv("JWT_SECRET", "dev-secret-change-me")

    if isinstance(subject_or_payload, (int, str)):
        payload: Dict[str, Any] = {"sub": str(subject_or_payload)}
    else:
        payload = dict(subject_or_payload)

    expire = utcnow() + timedelta(minutes=expires_minutes)
    payload["exp"] = expire
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_token(token: str, secret: Optional[str] = None) -> Dict[str, Any]:
    if secret is None:
        secret = os.getenv("JWT_SECRET", "dev-secret-change-me")
    return jwt.decode(token, secret, algorithms=["HS256"])
