"""Add validation schedules.

Revision ID: 039
Revises: 038
Create Date: 2026-04-26
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "039"
down_revision = "038"
branch_labels = None
depends_on = None


def _has_table(table_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return table_name in inspector.get_table_names()


def upgrade() -> None:
    if _has_table("scan_execution_artifacts"):
        inspector = sa.inspect(op.get_bind())
        columns = {column["name"] for column in inspector.get_columns("scan_execution_artifacts")}
        if "output_sha256" not in columns:
            op.add_column(
                "scan_execution_artifacts",
                sa.Column("output_sha256", sa.String(length=64), nullable=True),
            )

    if _has_table("validation_schedules"):
        return

    op.create_table(
        "validation_schedules",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("threat_model_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("owner_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_node_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("tool_name", sa.String(length=50), nullable=False),
        sa.Column("target_type", sa.String(length=50), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("scope", sa.String(length=20), nullable=False, server_default="external"),
        sa.Column("cadence", sa.String(length=20), nullable=False, server_default="manual"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("authorization_required", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("authorization_acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "tool_name IN ('nuclei','semgrep','osv-scanner','trivy','checkov')",
            name="ck_validation_schedules_tool_name",
        ),
        sa.CheckConstraint(
            "target_type IN ('url','repository_path','lockfile','container_image','iac_directory')",
            name="ck_validation_schedules_target_type",
        ),
        sa.CheckConstraint(
            "scope IN ('external','internal','full')",
            name="ck_validation_schedules_scope",
        ),
        sa.CheckConstraint(
            "cadence IN ('manual','daily','weekly','monthly')",
            name="ck_validation_schedules_cadence",
        ),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_node_id"], ["dfd_nodes.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["threat_model_id"], ["threat_models.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_validation_schedules_threat_model_enabled",
        "validation_schedules",
        ["threat_model_id", "enabled"],
    )
    op.create_index(
        "ix_validation_schedules_next_run_at",
        "validation_schedules",
        ["next_run_at"],
    )


def downgrade() -> None:
    if _has_table("validation_schedules"):
        op.drop_index("ix_validation_schedules_next_run_at", table_name="validation_schedules")
        op.drop_index("ix_validation_schedules_threat_model_enabled", table_name="validation_schedules")
        op.drop_table("validation_schedules")

    if _has_table("scan_execution_artifacts"):
        inspector = sa.inspect(op.get_bind())
        columns = {column["name"] for column in inspector.get_columns("scan_execution_artifacts")}
        if "output_sha256" in columns:
            op.drop_column("scan_execution_artifacts", "output_sha256")
