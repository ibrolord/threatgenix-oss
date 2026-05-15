"""Add optional scan credential expiry metadata.

Revision ID: 063
Revises: 062
Create Date: 2026-04-29
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "063"
down_revision = "062"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def _has_column(table: str, column: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(c["name"] == column for c in inspector.get_columns(table))


def _has_index(table: str, index: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(i["name"] == index for i in inspector.get_indexes(table))


def upgrade() -> None:
    if _has_table("scan_credentials") and not _has_column("scan_credentials", "expires_at"):
        op.add_column(
            "scan_credentials",
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        )
    if _has_table("scan_credentials") and not _has_index(
        "scan_credentials", "ix_scan_credentials_expires_at"
    ):
        op.create_index(
            "ix_scan_credentials_expires_at",
            "scan_credentials",
            ["expires_at"],
        )


def downgrade() -> None:
    if _has_table("scan_credentials") and _has_index(
        "scan_credentials", "ix_scan_credentials_expires_at"
    ):
        op.drop_index("ix_scan_credentials_expires_at", table_name="scan_credentials")
    if _has_table("scan_credentials") and _has_column("scan_credentials", "expires_at"):
        op.drop_column("scan_credentials", "expires_at")
