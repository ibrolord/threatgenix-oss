"""Add relevance_rationale column to threats table.

Revision ID: 002
Revises: 001
Create Date: 2026-04-03
"""

from alembic import op
import sqlalchemy as sa

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def _has_column(table_name: str, column_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def upgrade() -> None:
    if not _has_column("threats", "relevance_rationale"):
        op.add_column(
            "threats",
            sa.Column(
                "relevance_rationale",
                sa.Text(),
                nullable=True,
                comment="Contextual explanation of why this threat matters for this specific system",
            ),
        )


def downgrade() -> None:
    op.drop_column("threats", "relevance_rationale")
