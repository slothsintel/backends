# app/models.py
from datetime import datetime, timezone

from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import text

from .db import Base


def utcnow():
    return datetime.now(timezone.utc)


class OwUser(Base):
    __tablename__ = "ow_users"

    # DB column is uuid with default gen_random_uuid()
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)

    # Map API's "is_verified" attribute to DB column "is_email_verified"
    is_verified = Column(
        "is_email_verified",
        Boolean,
        nullable=False,
        server_default=text("false"),
    )

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

    # Match UUID user id
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("ow_users.id", ondelete="CASCADE"),
        nullable=False,
    )

    token_hash = Column(String, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)

    user = relationship("OwUser")