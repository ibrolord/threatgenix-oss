"""Add validation sandbox metadata to execution artifacts.

Revision ID: 040
Revises: 039
Create Date: 2026-04-26
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "040"
down_revision = "039"
branch_labels = None
depends_on = None


def _has_table(table_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return table_name in inspector.get_table_names()


def _has_column(table_name: str, column_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def upgrade() -> None:
    if not _has_table("scan_execution_artifacts"):
        return

    if not _has_column("scan_execution_artifacts", "sandbox_mode"):
        op.add_column(
            "scan_execution_artifacts",
            sa.Column("sandbox_mode", sa.String(length=30), nullable=True),
        )
    if not _has_column("scan_execution_artifacts", "container_image"):
        op.add_column(
            "scan_execution_artifacts",
            sa.Column("container_image", sa.Text(), nullable=True),
        )
    if not _has_column("scan_execution_artifacts", "resource_limits"):
        op.add_column(
            "scan_execution_artifacts",
            sa.Column(
                "resource_limits",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'{}'::jsonb"),
            ),
        )


def downgrade() -> None:
    if not _has_table("scan_execution_artifacts"):
        return

    if _has_column("scan_execution_artifacts", "resource_limits"):
        op.drop_column("scan_execution_artifacts", "resource_limits")
    if _has_column("scan_execution_artifacts", "container_image"):
        op.drop_column("scan_execution_artifacts", "container_image")
    if _has_column("scan_execution_artifacts", "sandbox_mode"):
        op.drop_column("scan_execution_artifacts", "sandbox_mode")
