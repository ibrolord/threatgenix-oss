"""Add scan target authorization proofs.

Revision ID: 067
Revises: 066
Create Date: 2026-04-30
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "067"
down_revision = "066"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "scan_target_authorizations" not in inspector.get_table_names():
        op.create_table(
            "scan_target_authorizations",
            sa.Column(
                "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
            ),
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
            sa.Column("hostname", sa.String(length=255), nullable=False),
            sa.Column("normalized_host", sa.String(length=255), nullable=False),
            sa.Column("target_url", sa.Text(), nullable=True),
            sa.Column("proof_method", sa.String(length=40), nullable=False),
            sa.Column("proof_reference", sa.Text(), nullable=True),
            sa.Column(
                "status",
                sa.String(length=20),
                server_default="verified",
                nullable=False,
            ),
            sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
            sa.CheckConstraint(
                "status IN ('verified','expired','revoked')",
                name="ck_scan_target_authorizations_status",
            ),
            sa.CheckConstraint(
                "proof_method IN ('dns_txt','http_file','manual_admin','synthetic_test')",
                name="ck_scan_target_authorizations_proof_method",
            ),
        )
        existing_indexes: set[str] = set()
    else:
        existing_indexes = {
            index["name"]
            for index in inspector.get_indexes("scan_target_authorizations")
        }
    if "ix_scan_target_authorizations_lookup" not in existing_indexes:
        op.create_index(
            "ix_scan_target_authorizations_lookup",
            "scan_target_authorizations",
            ["owner_id", "threat_model_id", "normalized_host", "status"],
        )
    if "ix_scan_target_authorizations_expires" not in existing_indexes:
        op.create_index(
            "ix_scan_target_authorizations_expires",
            "scan_target_authorizations",
            ["expires_at"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "scan_target_authorizations" not in inspector.get_table_names():
        return
    existing_indexes = {
        index["name"]
        for index in inspector.get_indexes("scan_target_authorizations")
    }
    if "ix_scan_target_authorizations_expires" in existing_indexes:
        op.drop_index(
            "ix_scan_target_authorizations_expires",
            table_name="scan_target_authorizations",
        )
    if "ix_scan_target_authorizations_lookup" in existing_indexes:
        op.drop_index(
            "ix_scan_target_authorizations_lookup",
            table_name="scan_target_authorizations",
        )
    op.drop_table("scan_target_authorizations")
