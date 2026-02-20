"""add welcome_sent and soft delete columns

Revision ID: 388aacbce789
Revises: 0002_ow_users_tokens
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = "388aacbce789"
down_revision = "0002_ow_users_tokens"
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    bind = op.get_bind()
    insp = inspect(bind)
    cols = [c["name"] for c in insp.get_columns(table)]
    return column in cols


def upgrade():
    # ow_users.welcome_sent
    if not _has_column("ow_users", "welcome_sent"):
        op.add_column(
            "ow_users",
            sa.Column("welcome_sent", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        )

    # ow_users.welcome_sent_at
    if not _has_column("ow_users", "welcome_sent_at"):
        op.add_column(
            "ow_users",
            sa.Column("welcome_sent_at", sa.DateTime(timezone=True), nullable=True),
        )

    # ow_users.is_deleted
    if not _has_column("ow_users", "is_deleted"):
        op.add_column(
            "ow_users",
            sa.Column("is_deleted", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        )

    # ow_users.deleted_at
    if not _has_column("ow_users", "deleted_at"):
        op.add_column(
            "ow_users",
            sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        )

    # Optional tidy-up: remove server defaults after backfilling
    # (safe to leave as-is; uncomment if you want)
    # if _has_column("ow_users", "welcome_sent"):
    #     op.alter_column("ow_users", "welcome_sent", server_default=None)
    # if _has_column("ow_users", "is_deleted"):
    #     op.alter_column("ow_users", "is_deleted", server_default=None)


def downgrade():
    # Make downgrade also safe
    if _has_column("ow_users", "deleted_at"):
        op.drop_column("ow_users", "deleted_at")
    if _has_column("ow_users", "is_deleted"):
        op.drop_column("ow_users", "is_deleted")
    if _has_column("ow_users", "welcome_sent_at"):
        op.drop_column("ow_users", "welcome_sent_at")
    if _has_column("ow_users", "welcome_sent"):
        op.drop_column("ow_users", "welcome_sent")