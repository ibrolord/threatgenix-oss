"""Add dfd_component_templates JSONB column to threat_models.

Revision ID: 019
Revises: 018
Create Date: 2026-04-16
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "019"
down_revision = "018"
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(c["name"] == column for c in inspector.get_columns(table))


def upgrade() -> None:
    if not _has_column("threat_models", "dfd_component_templates"):
        op.add_column(
            "threat_models",
            sa.Column(
                "dfd_component_templates",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=True,
            ),
        )


def downgrade() -> None:
    if _has_column("threat_models", "dfd_component_templates"):
        op.drop_column("threat_models", "dfd_component_templates")
