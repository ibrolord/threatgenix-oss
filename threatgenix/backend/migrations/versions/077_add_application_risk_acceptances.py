"""Add application risk acceptance lifecycle table.

Revision ID: 077
Revises: 076
Create Date: 2026-05-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "077"
down_revision = "076"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "application_risk_acceptances" in inspector.get_table_names():
        return
    op.create_table(
        "application_risk_acceptances",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("tenant_key", sa.String(length=80), nullable=False),
        sa.Column("app_name", sa.String(length=255), nullable=False),
        sa.Column("review_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_stable_id", sa.String(length=255), nullable=True),
        sa.Column("scope_type", sa.String(length=20), nullable=False),
        sa.Column("scope_value", sa.String(length=500), nullable=False),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("compensating_control", sa.Text(), nullable=True),
        sa.Column("approver_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("revoked_reason", sa.Text(), nullable=True),
        sa.Column(
            "audit_events",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.CheckConstraint(
            "scope_type IN ('rule','finding','route','app')",
            name="ck_application_risk_acceptances_scope_type",
        ),
        sa.CheckConstraint(
            "status IN ('active','expired','revoked')",
            name="ck_application_risk_acceptances_status",
        ),
        sa.ForeignKeyConstraint(["review_id"], ["application_security_reviews.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["approver_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["revoked_by_id"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index(
        "ix_application_risk_acceptances_tenant_review",
        "application_risk_acceptances",
        ["tenant_key", "review_id"],
    )
    op.create_index(
        "ix_application_risk_acceptances_scope",
        "application_risk_acceptances",
        ["tenant_key", "scope_type", "scope_value"],
    )
    op.create_index(
        "ix_application_risk_acceptances_expiry",
        "application_risk_acceptances",
        ["status", "expires_at"],
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "application_risk_acceptances" not in inspector.get_table_names():
        return
    op.drop_index("ix_application_risk_acceptances_expiry", table_name="application_risk_acceptances")
    op.drop_index("ix_application_risk_acceptances_scope", table_name="application_risk_acceptances")
    op.drop_index("ix_application_risk_acceptances_tenant_review", table_name="application_risk_acceptances")
    op.drop_table("application_risk_acceptances")
