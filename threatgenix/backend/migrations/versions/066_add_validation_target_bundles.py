"""Add hosted validation target bundles.

Revision ID: 066
Revises: 065
Create Date: 2026-04-30
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "066"
down_revision = "065"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "validation_target_bundles" not in inspector.get_table_names():
        op.create_table(
            "validation_target_bundles",
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
            sa.Column(
                "organization_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("organizations.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("name", sa.String(length=200), nullable=False),
            sa.Column("filename", sa.String(length=500), nullable=False),
            sa.Column("content_type", sa.String(length=200), nullable=True),
            sa.Column("byte_size", sa.Integer(), nullable=False),
            sa.Column("sha256", sa.String(length=64), nullable=False),
            sa.Column(
                "status", sa.String(length=20), server_default="ready", nullable=False
            ),
            sa.Column(
                "storage_backend",
                sa.String(length=30),
                server_default="database",
                nullable=False,
            ),
            sa.Column("storage_key", sa.Text(), nullable=True),
            sa.Column("archive_bytes", sa.LargeBinary(), nullable=True),
            sa.Column(
                "manifest",
                postgresql.JSONB(astext_type=sa.Text()),
                server_default=sa.text("'{}'::jsonb"),
                nullable=False,
            ),
            sa.Column(
                "retention_expires_at", sa.DateTime(timezone=True), nullable=True
            ),
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
                "status IN ('ready','expired','deleted')",
                name="ck_validation_target_bundles_status",
            ),
            sa.CheckConstraint(
                "storage_backend IN ('database','object_store')",
                name="ck_validation_target_bundles_storage_backend",
            ),
        )
        existing_indexes: set[str] = set()
    else:
        existing_indexes = {
            index["name"]
            for index in inspector.get_indexes("validation_target_bundles")
        }
    if "ix_validation_target_bundles_threat_model_created" not in existing_indexes:
        op.create_index(
            "ix_validation_target_bundles_threat_model_created",
            "validation_target_bundles",
            ["threat_model_id", "created_at"],
        )
    if "ix_validation_target_bundles_owner" not in existing_indexes:
        op.create_index(
            "ix_validation_target_bundles_owner",
            "validation_target_bundles",
            ["owner_id"],
        )


def downgrade() -> None:
    op.drop_index(
        "ix_validation_target_bundles_owner", table_name="validation_target_bundles"
    )
    op.drop_index(
        "ix_validation_target_bundles_threat_model_created",
        table_name="validation_target_bundles",
    )
    op.drop_table("validation_target_bundles")
