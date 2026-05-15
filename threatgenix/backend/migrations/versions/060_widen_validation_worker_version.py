"""Widen validation worker heartbeat version metadata.

Revision ID: 060
Revises: 059
Create Date: 2026-04-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "060"
down_revision = "059"
branch_labels = None
depends_on = None


def _inspector():
    return sa.inspect(op.get_bind())


def _has_table(table_name: str) -> bool:
    return table_name in _inspector().get_table_names()


def _has_column(table_name: str, column_name: str) -> bool:
    if not _has_table(table_name):
        return False
    return any(
        column["name"] == column_name
        for column in _inspector().get_columns(table_name)
    )


def upgrade() -> None:
    if _has_column("validation_worker_heartbeats", "version"):
        with op.batch_alter_table("validation_worker_heartbeats") as batch_op:
            batch_op.alter_column(
                "version",
                existing_type=sa.String(50),
                type_=sa.String(200),
                existing_nullable=True,
            )


def downgrade() -> None:
    if _has_column("validation_worker_heartbeats", "version"):
        with op.batch_alter_table("validation_worker_heartbeats") as batch_op:
            batch_op.alter_column(
                "version",
                existing_type=sa.String(200),
                type_=sa.String(50),
                existing_nullable=True,
            )
