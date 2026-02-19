from alembic import op
import sqlalchemy as sa

revision = "0002_ow_users_tokens"
down_revision = "0001_ow_auth"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("ow_users", sa.Column("verify_token_hash", sa.Text(), nullable=True))
    op.add_column("ow_users", sa.Column("verify_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("ow_users", sa.Column("reset_token_hash", sa.Text(), nullable=True))
    op.add_column("ow_users", sa.Column("reset_expires_at", sa.DateTime(timezone=True), nullable=True))


def downgrade():
    op.drop_column("ow_users", "reset_expires_at")
    op.drop_column("ow_users", "reset_token_hash")
    op.drop_column("ow_users", "verify_expires_at")
    op.drop_column("ow_users", "verify_token_hash")
