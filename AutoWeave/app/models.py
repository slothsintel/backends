# app/models.py
from datetime import datetime, timezone

from zmq import NULL
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from .db import Base
from sqlalchemy import Boolean, DateTime


def utcnow():
    return datetime.now(timezone.utc)


class OwUser(Base):
    __tablename__ = "ow_users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)

    # IMPORTANT: keep name as is_verified to match what your API currently expects
    is_verified = Column(Boolean, nullable=False, default=False)

    verify_hash = Column(String, nullable=True)
    verify_expires_at = Column(DateTime(timezone=True), nullable=True)

    reset_hash = Column(String, nullable=True)
    reset_expires_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)

    welcome_sent = Column(Boolean, nullable=False, default=False)
    welcome_sent_at = Column(DateTime(timezone=True), nullable=True)

    is_deleted = Column(Boolean, nullable=False, default=False)
    deleted_at = Column(DateTime(timezone=True), nullable=True)


class OwPasswordReset(Base):
    __tablename__ = "ow_password_resets"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("ow_users.id", ondelete="CASCADE"), nullable=False)

    token_hash = Column(String, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)

    user = relationship("OwUser")