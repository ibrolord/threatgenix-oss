"""Add scan_credentials table and credential_id FK on scan_jobs.

Revision ID: 015
Revises: 014
Create Date: 2026-04-15
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "015"
down_revision = "014"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def _has_column(table: str, column: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(c["name"] == column for c in inspector.get_columns(table))


def upgrade() -> None:
    # 1. Create scan_credentials (must exist before scan_jobs FK can reference it)
    if not _has_table("scan_credentials"):
        op.create_table(
            "scan_credentials",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column(
                "threat_model_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("threat_models.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "owner_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("name", sa.String(200), nullable=False),
            sa.Column("credential_type", sa.String(30), nullable=False),
            sa.Column("header_name", sa.String(200), nullable=True),
            sa.Column("encrypted_secret", sa.Text, nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.CheckConstraint(
                "credential_type IN ('bearer_token','api_key_header','basic_auth','cookie')",
                name="ck_scan_credentials_type",
            ),
        )
        op.create_index(
            "ix_scan_credentials_threat_model_id",
            "scan_credentials",
            ["threat_model_id"],
        )

    # 2. Add credential_id FK to scan_jobs (nullable; SET NULL on credential delete)
    if _has_table("scan_jobs") and not _has_column("scan_jobs", "credential_id"):
        op.add_column(
            "scan_jobs",
            sa.Column(
                "credential_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("scan_credentials.id", ondelete="SET NULL"),
                nullable=True,
            ),
        )


def downgrade() -> None:
    if _has_table("scan_jobs") and _has_column("scan_jobs", "credential_id"):
        op.drop_column("scan_jobs", "credential_id")
    if _has_table("scan_credentials"):
        op.drop_index("ix_scan_credentials_threat_model_id", "scan_credentials")
        op.drop_table("scan_credentials")
