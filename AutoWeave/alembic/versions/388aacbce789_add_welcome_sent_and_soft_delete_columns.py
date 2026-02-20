"""add welcome_sent and soft delete columns

Revision ID: 388aacbce789
Revises: <PUT_YOUR_PREVIOUS_REVISION_ID_HERE>
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "388aacbce789"
down_revision = "0002_ow_users_tokens"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "ow_users",
        sa.Column("welcome_sent", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.add_column(
        "ow_users",
        sa.Column("welcome_sent_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "ow_users",
        sa.Column("is_deleted", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.add_column(
        "ow_users",
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade():
    op.drop_column("ow_users", "deleted_at")
    op.drop_column("ow_users", "is_deleted")
    op.drop_column("ow_users", "welcome_sent_at")
    op.drop_column("ow_users", "welcome_sent")