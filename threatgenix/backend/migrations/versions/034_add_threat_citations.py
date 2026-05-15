"""Add citations JSONB column to threats table.

Revision ID: 034
Revises: 033
Create Date: 2026-04-24
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "034"
down_revision = "033"
branch_labels = None
depends_on = None


def _has_column(table_name: str, column_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def upgrade() -> None:
    if not _has_column("threats", "citations"):
        op.add_column(
            "threats",
            sa.Column(
                "citations",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default="[]",
            ),
        )


def downgrade() -> None:
    if _has_column("threats", "citations"):
        op.drop_column("threats", "citations")
