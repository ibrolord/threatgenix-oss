"""Make validation worker heartbeat version unbounded.

Revision ID: 061
Revises: 060
Create Date: 2026-04-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "061"
down_revision = "060"
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
        op.execute(
            "ALTER TABLE validation_worker_heartbeats "
            "ALTER COLUMN version TYPE TEXT USING version::text"
        )


def downgrade() -> None:
    if _has_column("validation_worker_heartbeats", "version"):
        op.execute(
            "ALTER TABLE validation_worker_heartbeats "
            "ALTER COLUMN version TYPE VARCHAR(200) USING left(version, 200)"
        )
