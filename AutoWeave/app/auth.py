import os
import hashlib
from datetime import datetime, timedelta
from typing import Optional

import bcrypt
from jose import jwt, JWTError

JWT_SECRET = (os.getenv("SECRET_KEY") or os.getenv("JWT_SECRET") or "").strip()
if not JWT_SECRET:
    JWT_SECRET = "dev-secret-change-me"

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = int(os.getenv("ACCESS_TOKEN_EXPIRE_HOURS", "168"))  # 7 days


def _bcrypt_input(password: str) -> bytes:
    """
    bcrypt only accepts up to 72 bytes.
    If longer, pre-hash to 32 bytes (SHA-256) first.
    """
    raw = password.encode("utf-8")
    if len(raw) <= 72:
        return raw
    return hashlib.sha256(raw).digest()


def hash_password(password: str) -> str:
    pw = _bcrypt_input(password)
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(pw, salt).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    pw = _bcrypt_input(password)
    try:
        return bcrypt.checkpw(pw, password_hash.encode("utf-8"))
    except Exception:
        return False


def create_access_token(user_id: str) -> str:
    exp = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    payload = {"sub": user_id, "exp": exp}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


def safe_decode_sub(token: str) -> Optional[str]:
    try:
        payload = decode_access_token(token)
        return payload.get("sub")
    except JWTError:
        return None
