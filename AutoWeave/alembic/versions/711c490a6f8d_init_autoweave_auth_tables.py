from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_ow_auth"
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # enable gen_random_uuid()
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")

    op.create_table(
        "ow_users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("email", sa.Text(), nullable=False, unique=True),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("is_email_verified", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("idx_ow_users_email", "ow_users", ["email"])

    op.create_table(
        "ow_password_resets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["user_id"], ["ow_users.id"], ondelete="CASCADE"),
    )
    op.create_index("idx_ow_pwreset_user", "ow_password_resets", ["user_id"])
    op.create_index("idx_ow_pwreset_expires", "ow_password_resets", ["expires_at"])

def downgrade():
    op.drop_index("idx_ow_pwreset_expires", table_name="ow_password_resets")
    op.drop_index("idx_ow_pwreset_user", table_name="ow_password_resets")
    op.drop_table("ow_password_resets")

    op.drop_index("idx_ow_users_email", table_name="ow_users")
    op.drop_table("ow_users")
