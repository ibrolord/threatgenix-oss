"""Add shared reusable report template library to users.

Revision ID: 028
Revises: 027
Create Date: 2026-04-18
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "028"
down_revision = "027"
branch_labels = None
depends_on = None


def _has_column(table_name: str, column_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def upgrade() -> None:
    if not _has_column("users", "report_template_library"):
        op.add_column(
            "users",
            sa.Column(
                "report_template_library",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=True,
                comment="User-scoped reusable report templates available across threat models.",
            ),
        )


def downgrade() -> None:
    pass
