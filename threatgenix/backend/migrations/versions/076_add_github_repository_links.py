"""Add GitHub repository links for PR reviews.

Revision ID: 076
Revises: 075
Create Date: 2026-05-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "076"
down_revision = "075"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "github_repository_links" in inspector.get_table_names():
        return
    op.create_table(
        "github_repository_links",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("tenant_key", sa.String(length=80), nullable=False),
        sa.Column("owner_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("threat_model_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("installation_id", sa.String(length=80), nullable=False),
        sa.Column("repository_id", sa.String(length=80), nullable=False),
        sa.Column("repository_full_name", sa.String(length=255), nullable=False),
        sa.Column("private", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("requested_tools", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="[]"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.CheckConstraint(
            "status IN ('active','suspended','uninstalled')",
            name="ck_github_repository_links_status",
        ),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["threat_model_id"], ["threat_models.id"], ondelete="SET NULL"),
        sa.UniqueConstraint(
            "installation_id",
            "repository_id",
            name="uq_github_repository_links_installation_repo",
        ),
    )
    op.create_index("ix_github_repository_links_tenant", "github_repository_links", ["tenant_key"])
    op.create_index("ix_github_repository_links_owner", "github_repository_links", ["owner_id"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "github_repository_links" not in inspector.get_table_names():
        return
    op.drop_index("ix_github_repository_links_owner", table_name="github_repository_links")
    op.drop_index("ix_github_repository_links_tenant", table_name="github_repository_links")
    op.drop_table("github_repository_links")
