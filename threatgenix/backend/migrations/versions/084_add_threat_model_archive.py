"""Add soft archive timestamp to threat models.

Revision ID: 084
Revises: 083
Create Date: 2026-05-15
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "084"
down_revision = "083"
branch_labels = None
depends_on = None


def _columns(table_name: str) -> set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if table_name not in inspector.get_table_names():
        return set()
    return {column["name"] for column in inspector.get_columns(table_name)}


def _indexes(table_name: str) -> set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if table_name not in inspector.get_table_names():
        return set()
    return {index["name"] for index in inspector.get_indexes(table_name)}


def upgrade() -> None:
    columns = _columns("threat_models")
    if not columns:
        return
    if columns and "archived_at" not in columns:
        op.add_column(
            "threat_models",
            sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        )

    indexes = _indexes("threat_models")
    if "ix_threat_models_archived_at" not in indexes:
        op.create_index(
            "ix_threat_models_archived_at",
            "threat_models",
            ["archived_at"],
        )


def downgrade() -> None:
    indexes = _indexes("threat_models")
    if "ix_threat_models_archived_at" in indexes:
        op.drop_index("ix_threat_models_archived_at", table_name="threat_models")

    columns = _columns("threat_models")
    if "archived_at" in columns:
        op.drop_column("threat_models", "archived_at")
