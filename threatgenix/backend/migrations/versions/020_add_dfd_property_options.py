"""Add dfd_property_options JSONB column to threat_models.

Revision ID: 020
Revises: 019
Create Date: 2026-04-16
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "020"
down_revision = "019"
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(c["name"] == column for c in inspector.get_columns(table))


def upgrade() -> None:
    if not _has_column("threat_models", "dfd_property_options"):
        op.add_column(
            "threat_models",
            sa.Column(
                "dfd_property_options",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=True,
            ),
        )


def downgrade() -> None:
    if _has_column("threat_models", "dfd_property_options"):
        op.drop_column("threat_models", "dfd_property_options")
