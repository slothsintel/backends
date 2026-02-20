# app/db.py
import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def ensure_schema():
    """
    Lightweight, idempotent schema upgrades (no Alembic required).
    This prevents crashes like: column ow_users.is_verified does not exist.
    """
    with engine.begin() as conn:
        # Ensure ow_users table exists (if you already create via Alembic, this does nothing harmful)
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS ow_users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """))

        # Add missing columns used by auth flows
        conn.execute(text("ALTER TABLE ow_users ADD COLUMN IF NOT EXISTS is_verified BOOLEAN NOT NULL DEFAULT FALSE"))
        conn.execute(text("ALTER TABLE ow_users ADD COLUMN IF NOT EXISTS verify_hash TEXT"))
        conn.execute(text("ALTER TABLE ow_users ADD COLUMN IF NOT EXISTS verify_expires_at TIMESTAMPTZ"))
        conn.execute(text("ALTER TABLE ow_users ADD COLUMN IF NOT EXISTS reset_hash TEXT"))
        conn.execute(text("ALTER TABLE ow_users ADD COLUMN IF NOT EXISTS reset_expires_at TIMESTAMPTZ"))

        # updated_at auto-maintain (optional)
        conn.execute(text("ALTER TABLE ow_users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()"))

        # Password reset table (optional; keep if you use it)
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS ow_password_resets (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES ow_users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            used_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """))