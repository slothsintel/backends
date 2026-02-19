from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Text
from sqlalchemy.sql import text as sql_text
from sqlalchemy.orm import relationship

from .db import Base


# --- UUID support that works on Postgres, and remains importable on SQLite ---
try:
    from sqlalchemy.dialects.postgresql import UUID  # type: ignore
    _HAS_PG_UUID = True
except Exception:
    UUID = None  # type: ignore
    _HAS_PG_UUID = False


class OwUser(Base):
    __tablename__ = "ow_users"

    if _HAS_PG_UUID:
        id = Column(UUID(as_uuid=True), primary_key=True, server_default=sql_text("gen_random_uuid()"))
    else:
        # Allows local import on SQLite; Postgres should use UUID
        id = Column(Text, primary_key=True)

    email = Column(Text, unique=True, nullable=False)
    password_hash = Column(Text, nullable=False)
    is_email_verified = Column(Boolean, nullable=False, server_default=sql_text("false"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=sql_text("now()"))

    # AutoTrac-style: store tokens directly on user
    verify_token_hash = Column(Text, nullable=True)
    verify_expires_at = Column(DateTime(timezone=True), nullable=True)

    reset_token_hash = Column(Text, nullable=True)
    reset_expires_at = Column(DateTime(timezone=True), nullable=True)

    # Keep this model if you already have ow_password_resets table (safe to keep unused)
    password_resets = relationship("OwPasswordReset", back_populates="user", cascade="all, delete-orphan")


class OwPasswordReset(Base):
    """
    Legacy/optional table (you already created it earlier).
    Not required if you store reset token directly on ow_users,
    but keeping it avoids breaking existing DB state.
    """
    __tablename__ = "ow_password_resets"

    if _HAS_PG_UUID:
        id = Column(UUID(as_uuid=True), primary_key=True, server_default=sql_text("gen_random_uuid()"))
        user_id = Column(UUID(as_uuid=True), ForeignKey("ow_users.id", ondelete="CASCADE"), nullable=False)
    else:
        id = Column(Text, primary_key=True)
        user_id = Column(Text, ForeignKey("ow_users.id", ondelete="CASCADE"), nullable=False)

    token_hash = Column(Text, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=sql_text("now()"))

    user = relationship("OwUser", back_populates="password_resets")
