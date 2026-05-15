"""Add application review context entries.

Revision ID: 070
Revises: 069
Create Date: 2026-05-01
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "070"
down_revision = "069"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "application_review_context_entries" not in inspector.get_table_names():
        op.create_table(
            "application_review_context_entries",
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
            sa.Column("source_type", sa.String(length=40), nullable=False),
            sa.Column("source_object_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("item_type", sa.String(length=40), nullable=False),
            sa.Column("title", sa.String(length=500), nullable=False),
            sa.Column("body", sa.Text(), nullable=False),
            sa.Column(
                "keywords",
                postgresql.JSONB(astext_type=sa.Text()),
                server_default=sa.text("'[]'::jsonb"),
                nullable=False,
            ),
            sa.Column(
                "source_refs",
                postgresql.JSONB(astext_type=sa.Text()),
                server_default=sa.text("'[]'::jsonb"),
                nullable=False,
            ),
            sa.Column("content_hash", sa.String(length=64), nullable=False),
            sa.Column("status", sa.String(length=20), server_default="active", nullable=False),
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
                "source_type IN ('review','bundle','scan_finding','policy','manual')",
                name="ck_application_review_context_entries_source_type",
            ),
            sa.CheckConstraint(
                "item_type IN ('app_profile','org_profile','review_scope','bundle_file',"
                "'scanner_finding','policy','accepted_risk','note')",
                name="ck_application_review_context_entries_item_type",
            ),
            sa.CheckConstraint(
                "status IN ('active','stale','deleted')",
                name="ck_application_review_context_entries_status",
            ),
        )

    existing_indexes = {
        index["name"]
        for index in inspector.get_indexes("application_review_context_entries")
    }
    if "ix_application_review_context_tenant_review" not in existing_indexes:
        op.create_index(
            "ix_application_review_context_tenant_review",
            "application_review_context_entries",
            ["tenant_key", "review_id", "status"],
        )
    if "ix_application_review_context_source_object" not in existing_indexes:
        op.create_index(
            "ix_application_review_context_source_object",
            "application_review_context_entries",
            ["source_type", "source_object_id"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "application_review_context_entries" not in inspector.get_table_names():
        return
    existing_indexes = {
        index["name"]
        for index in inspector.get_indexes("application_review_context_entries")
    }
    for index_name in (
        "ix_application_review_context_source_object",
        "ix_application_review_context_tenant_review",
    ):
        if index_name in existing_indexes:
            op.drop_index(index_name, table_name="application_review_context_entries")
    op.drop_table("application_review_context_entries")
