"""Add durable validation execution artifacts.

Revision ID: 037
Revises: 036
Create Date: 2026-04-26
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "037"
down_revision = "036"
branch_labels = None
depends_on = None


def _has_table(table_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return table_name in inspector.get_table_names()


def upgrade() -> None:
    if _has_table("scan_execution_artifacts"):
        return

    op.create_table(
        "scan_execution_artifacts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "scan_job_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source", sa.String(20), nullable=False, server_default="execution"),
        sa.Column("tool_name", sa.String(50), nullable=False),
        sa.Column("target_type", sa.String(50), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("resolved_target", sa.Text(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="completed"),
        sa.Column("deterministic", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("sandboxed", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("policy_decision", sa.Text(), nullable=True),
        sa.Column(
            "command",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("command_redacted", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("returncode", sa.Integer(), nullable=True),
        sa.Column("timed_out", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "output_limit_exceeded",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("stdout_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("stderr_summary", sa.Text(), nullable=True),
        sa.Column("network_mode", sa.String(30), nullable=True),
        sa.Column("max_runtime_seconds", sa.Integer(), nullable=True),
        sa.Column("max_output_bytes", sa.Integer(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.CheckConstraint(
            "source IN ('execution','ingest')",
            name="ck_scan_execution_artifacts_source",
        ),
        sa.CheckConstraint(
            "status IN ('completed','failed','timed_out','blocked')",
            name="ck_scan_execution_artifacts_status",
        ),
    )
    op.create_index(
        "ix_scan_execution_artifacts_scan_job_id",
        "scan_execution_artifacts",
        ["scan_job_id"],
    )


def downgrade() -> None:
    if _has_table("scan_execution_artifacts"):
        op.drop_index(
            "ix_scan_execution_artifacts_scan_job_id",
            table_name="scan_execution_artifacts",
        )
        op.drop_table("scan_execution_artifacts")
