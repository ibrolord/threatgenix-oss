"""Add arch_diagrams JSONB to threat_models for multi-diagram PDF reports.

Revision ID: 008
Revises: 007
Create Date: 2026-04-15
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "008"
down_revision = "007"
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(existing["name"] == column for existing in inspector.get_columns(table))


def upgrade() -> None:
    if not _has_column("threat_models", "arch_diagrams"):
        op.add_column(
            "threat_models",
            sa.Column(
                "arch_diagrams",
                JSONB,
                nullable=True,
                comment="List of {name, image_base64} architectural diagrams for PDF report.",
            ),
        )


def downgrade() -> None:
    if _has_column("threat_models", "arch_diagrams"):
        op.drop_column("threat_models", "arch_diagrams")
