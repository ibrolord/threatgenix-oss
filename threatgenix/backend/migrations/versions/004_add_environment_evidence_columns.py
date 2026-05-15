"""Add optional repository and cloud scan evidence fields to threat models.

Revision ID: 004
Revises: 003
Create Date: 2026-04-13
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def _has_column(table_name: str, column_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def upgrade() -> None:
    if not _has_column("threat_models", "repository_evidence"):
        op.add_column(
            "threat_models",
            sa.Column("repository_evidence", JSONB, nullable=True),
        )
    if not _has_column("threat_models", "cloud_scan_evidence"):
        op.add_column(
            "threat_models",
            sa.Column("cloud_scan_evidence", JSONB, nullable=True),
        )
    if not _has_column("threat_models", "environment_context_summary"):
        op.add_column(
            "threat_models",
            sa.Column("environment_context_summary", sa.Text(), nullable=True),
        )


def downgrade() -> None:
    op.drop_column("threat_models", "environment_context_summary")
    op.drop_column("threat_models", "cloud_scan_evidence")
    op.drop_column("threat_models", "repository_evidence")
