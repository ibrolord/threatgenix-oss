"""Add custom structured report templates to threat models.

Revision ID: 027
Revises: 026
Create Date: 2026-04-18
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "027"
down_revision = "026"
branch_labels = None
depends_on = None


def _has_column(table_name: str, column_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def upgrade() -> None:
    if not _has_column("threat_models", "report_templates"):
        op.add_column(
            "threat_models",
            sa.Column(
                "report_templates",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=True,
                comment="Custom structured report templates defined for this threat model.",
            ),
        )


def downgrade() -> None:
    pass
