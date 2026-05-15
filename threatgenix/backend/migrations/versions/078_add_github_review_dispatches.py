"""Add GitHub review dispatch outbox.

Revision ID: 078
Revises: 077
Create Date: 2026-05-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "078"
down_revision = "077"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "github_review_dispatches" in inspector.get_table_names():
        return
    op.create_table(
        "github_review_dispatches",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("tenant_key", sa.String(length=80), nullable=False),
        sa.Column("review_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("installation_id", sa.String(length=80), nullable=False),
        sa.Column("repository_id", sa.String(length=80), nullable=False),
        sa.Column("repository_full_name", sa.String(length=255), nullable=False),
        sa.Column("pull_request_number", sa.Integer(), nullable=False),
        sa.Column("head_sha", sa.String(length=80), nullable=False),
        sa.Column("status_context", sa.String(length=120), nullable=False),
        sa.Column("review_status", sa.String(length=32), nullable=False),
        sa.Column("review_decision", sa.String(length=40), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="queued"),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("comment_id", sa.Integer(), nullable=True),
        sa.Column("status_state", sa.String(length=20), nullable=True),
        sa.Column("target_url", sa.Text(), nullable=True),
        sa.Column("queued_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "status IN ('queued','dispatching','dispatched','retryable_failed','terminal_failed')",
            name="ck_github_review_dispatches_status",
        ),
        sa.CheckConstraint(
            "status_state IS NULL OR status_state IN ('success','failure','pending','error')",
            name="ck_github_review_dispatches_status_state",
        ),
        sa.ForeignKeyConstraint(["review_id"], ["application_security_reviews.id"], ondelete="CASCADE"),
        sa.UniqueConstraint(
            "tenant_key",
            "review_id",
            "repository_id",
            "pull_request_number",
            "head_sha",
            "status_context",
            name="uq_github_review_dispatches_review_sha_context",
        ),
    )
    op.create_index("ix_github_review_dispatches_status", "github_review_dispatches", ["status", "queued_at"])
    op.create_index("ix_github_review_dispatches_review", "github_review_dispatches", ["review_id"])
    op.create_index("ix_github_review_dispatches_tenant", "github_review_dispatches", ["tenant_key"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "github_review_dispatches" not in inspector.get_table_names():
        return
    op.drop_index("ix_github_review_dispatches_tenant", table_name="github_review_dispatches")
    op.drop_index("ix_github_review_dispatches_review", table_name="github_review_dispatches")
    op.drop_index("ix_github_review_dispatches_status", table_name="github_review_dispatches")
    op.drop_table("github_review_dispatches")
