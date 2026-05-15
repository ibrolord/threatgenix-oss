"""Add application review bundles.

Revision ID: 069
Revises: 068
Create Date: 2026-05-01
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "069"
down_revision = "068"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "application_review_bundles" not in inspector.get_table_names():
        op.create_table(
            "application_review_bundles",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
            sa.Column("tenant_key", sa.String(length=80), nullable=False),
            sa.Column(
                "review_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("application_security_reviews.id", ondelete="CASCADE"),
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
            sa.Column("bundle_kind", sa.String(length=40), nullable=False),
            sa.Column("source", sa.String(length=40), nullable=False),
            sa.Column("status", sa.String(length=20), server_default="ready", nullable=False),
            sa.Column(
                "manifest",
                postgresql.JSONB(astext_type=sa.Text()),
                server_default=sa.text("'[]'::jsonb"),
                nullable=False,
            ),
            sa.Column("content_hash", sa.String(length=64), nullable=False),
            sa.Column("byte_size", sa.Integer(), nullable=False),
            sa.Column("file_count", sa.Integer(), nullable=False),
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
                "bundle_kind IN ('diff','snapshot','metadata')",
                name="ck_application_review_bundles_kind",
            ),
            sa.CheckConstraint(
                "source IN ('cli','github','api')",
                name="ck_application_review_bundles_source",
            ),
            sa.CheckConstraint(
                "status IN ('ready','deleted')",
                name="ck_application_review_bundles_status",
            ),
        )

    existing_indexes = {
        index["name"]
        for index in inspector.get_indexes("application_review_bundles")
    }
    if "ix_application_review_bundles_tenant_review" not in existing_indexes:
        op.create_index(
            "ix_application_review_bundles_tenant_review",
            "application_review_bundles",
            ["tenant_key", "review_id"],
        )
    if "ix_application_review_bundles_content_hash" not in existing_indexes:
        op.create_index(
            "ix_application_review_bundles_content_hash",
            "application_review_bundles",
            ["tenant_key", "review_id", "content_hash"],
            unique=True,
        )
    if "ix_application_review_bundles_organization_id" not in existing_indexes:
        op.create_index(
            "ix_application_review_bundles_organization_id",
            "application_review_bundles",
            ["organization_id"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "application_review_bundles" not in inspector.get_table_names():
        return
    existing_indexes = {
        index["name"]
        for index in inspector.get_indexes("application_review_bundles")
    }
    for index_name in (
        "ix_application_review_bundles_organization_id",
        "ix_application_review_bundles_content_hash",
        "ix_application_review_bundles_tenant_review",
    ):
        if index_name in existing_indexes:
            op.drop_index(index_name, table_name="application_review_bundles")
    op.drop_table("application_review_bundles")
