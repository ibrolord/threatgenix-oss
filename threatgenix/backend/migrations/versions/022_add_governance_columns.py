"""Add threat model governance JSONB columns.

Revision ID: 022
Revises: 021
Create Date: 2026-04-16
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "022"
down_revision = "021"
branch_labels = None
depends_on = None


def _has_column(table_name: str, column_name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return any(col["name"] == column_name for col in inspector.get_columns(table_name))


def upgrade() -> None:
    if not _has_column("threat_models", "model_snapshots"):
        op.add_column(
            "threat_models",
            sa.Column("model_snapshots", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        )
    if not _has_column("threat_models", "review_records"):
        op.add_column(
            "threat_models",
            sa.Column("review_records", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        )
    if not _has_column("threat_models", "control_library"):
        op.add_column(
            "threat_models",
            sa.Column("control_library", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        )


def downgrade() -> None:
    if _has_column("threat_models", "control_library"):
        op.drop_column("threat_models", "control_library")
    if _has_column("threat_models", "review_records"):
        op.drop_column("threat_models", "review_records")
    if _has_column("threat_models", "model_snapshots"):
        op.drop_column("threat_models", "model_snapshots")
