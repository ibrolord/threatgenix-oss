"""Add invoke-anywhere application security reviews.

Revision ID: 068
Revises: 067
Create Date: 2026-05-01
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "068"
down_revision = "067"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "application_security_reviews" not in inspector.get_table_names():
        op.create_table(
            "application_security_reviews",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
            sa.Column("tenant_key", sa.String(length=80), nullable=False),
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
            sa.Column(
                "threat_model_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("threat_models.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "parent_review_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("application_security_reviews.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("review_lineage_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("app_name", sa.String(length=255), nullable=False),
            sa.Column("invocation_surface", sa.String(length=40), nullable=False),
            sa.Column("input_kind", sa.String(length=40), nullable=False),
            sa.Column("status", sa.String(length=20), server_default="pending", nullable=False),
            sa.Column("decision", sa.String(length=40), nullable=True),
            sa.Column("commit_sha", sa.String(length=80), nullable=True),
            sa.Column("bundle_hash", sa.String(length=80), nullable=True),
            sa.Column("scope_fingerprint", sa.String(length=64), nullable=False),
            sa.Column("idempotency_key", sa.String(length=120), nullable=False),
            sa.Column(
                "requested_tools",
                postgresql.JSONB(astext_type=sa.Text()),
                server_default=sa.text("'[]'::jsonb"),
                nullable=False,
            ),
            sa.Column(
                "scope",
                postgresql.JSONB(astext_type=sa.Text()),
                server_default=sa.text("'{}'::jsonb"),
                nullable=False,
            ),
            sa.Column(
                "context",
                postgresql.JSONB(astext_type=sa.Text()),
                server_default=sa.text("'{}'::jsonb"),
                nullable=False,
            ),
            sa.Column(
                "policy",
                postgresql.JSONB(astext_type=sa.Text()),
                server_default=sa.text("'{}'::jsonb"),
                nullable=False,
            ),
            sa.Column("result_summary", sa.Text(), nullable=True),
            sa.Column("error_message", sa.Text(), nullable=True),
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
                "status IN ('pending','running','completed','failed','cancelled')",
                name="ck_application_security_reviews_status",
            ),
            sa.CheckConstraint(
                "decision IS NULL OR decision IN ('pass','block','fix','verify','gather_evidence')",
                name="ck_application_security_reviews_decision",
            ),
            sa.CheckConstraint(
                "invocation_surface IN ('cli','mcp','api','pr','web')",
                name="ck_application_security_reviews_invocation_surface",
            ),
            sa.CheckConstraint(
                "input_kind IN ('diff','snapshot','metadata')",
                name="ck_application_security_reviews_input_kind",
            ),
        )

    existing_indexes = {
        index["name"]
        for index in inspector.get_indexes("application_security_reviews")
    }
    if "ix_application_security_reviews_tenant_created" not in existing_indexes:
        op.create_index(
            "ix_application_security_reviews_tenant_created",
            "application_security_reviews",
            ["tenant_key", "created_at"],
        )
    if "ix_application_security_reviews_threat_model_created" not in existing_indexes:
        op.create_index(
            "ix_application_security_reviews_threat_model_created",
            "application_security_reviews",
            ["threat_model_id", "created_at"],
        )
    if "ix_application_security_reviews_lineage" not in existing_indexes:
        op.create_index(
            "ix_application_security_reviews_lineage",
            "application_security_reviews",
            ["review_lineage_id", "created_at"],
        )
    if "ix_application_security_reviews_idempotency" not in existing_indexes:
        op.create_index(
            "ix_application_security_reviews_idempotency",
            "application_security_reviews",
            ["tenant_key", "idempotency_key"],
            unique=True,
        )
    if "ix_application_security_reviews_organization_id" not in existing_indexes:
        op.create_index(
            "ix_application_security_reviews_organization_id",
            "application_security_reviews",
            ["organization_id"],
        )
    if "ix_application_security_reviews_threat_model_id" not in existing_indexes:
        op.create_index(
            "ix_application_security_reviews_threat_model_id",
            "application_security_reviews",
            ["threat_model_id"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "application_security_reviews" not in inspector.get_table_names():
        return
    existing_indexes = {
        index["name"]
        for index in inspector.get_indexes("application_security_reviews")
    }
    for index_name in (
        "ix_application_security_reviews_threat_model_id",
        "ix_application_security_reviews_organization_id",
        "ix_application_security_reviews_idempotency",
        "ix_application_security_reviews_lineage",
        "ix_application_security_reviews_threat_model_created",
        "ix_application_security_reviews_tenant_created",
    ):
        if index_name in existing_indexes:
            op.drop_index(index_name, table_name="application_security_reviews")
    op.drop_table("application_security_reviews")
