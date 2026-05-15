"""Add durable orchestration job tables.

Revision ID: 052
Revises: 051
Create Date: 2026-04-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "052"
down_revision = "051"
branch_labels = None
depends_on = None


def _has_table(table_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return table_name in inspector.get_table_names()


def _jsonb_empty_array():
    return sa.text("'[]'::jsonb")


def _jsonb_empty_object():
    return sa.text("'{}'::jsonb")


def upgrade() -> None:
    if not _has_table("orchestration_jobs"):
        op.create_table(
            "orchestration_jobs",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
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
            sa.Column("job_kind", sa.String(40), nullable=False),
            sa.Column(
                "status",
                sa.String(20),
                nullable=False,
                server_default="pending",
            ),
            sa.Column("objective", sa.Text(), nullable=False),
            sa.Column(
                "requested_tools",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=_jsonb_empty_array(),
            ),
            sa.Column(
                "inputs",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=_jsonb_empty_object(),
            ),
            sa.Column(
                "policy",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=_jsonb_empty_object(),
            ),
            sa.Column("result_summary", sa.Text(), nullable=True),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
            sa.CheckConstraint(
                "job_kind IN ('evidence_rebuild','validation_run','security_audit','environment_audit','custom')",
                name="ck_orchestration_jobs_kind",
            ),
            sa.CheckConstraint(
                "status IN ('pending','running','completed','failed','cancelled')",
                name="ck_orchestration_jobs_status",
            ),
        )
        op.create_index(
            "ix_orchestration_jobs_threat_model_status",
            "orchestration_jobs",
            ["threat_model_id", "status"],
        )
        op.create_index(
            "ix_orchestration_jobs_owner_created",
            "orchestration_jobs",
            ["owner_id", "created_at"],
        )

    if not _has_table("orchestration_tasks"):
        op.create_table(
            "orchestration_tasks",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column(
                "job_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("orchestration_jobs.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "threat_model_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("threat_models.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("task_kind", sa.String(40), nullable=False),
            sa.Column("agent_name", sa.String(120), nullable=True),
            sa.Column("tool_name", sa.String(120), nullable=True),
            sa.Column(
                "status",
                sa.String(20),
                nullable=False,
                server_default="pending",
            ),
            sa.Column(
                "input_payload",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=_jsonb_empty_object(),
            ),
            sa.Column(
                "output_payload",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=_jsonb_empty_object(),
            ),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
            sa.CheckConstraint(
                "task_kind IN ('agent_reasoning','tool_execution','evidence_projection','human_review')",
                name="ck_orchestration_tasks_kind",
            ),
            sa.CheckConstraint(
                "status IN ('pending','running','completed','failed','cancelled','blocked')",
                name="ck_orchestration_tasks_status",
            ),
        )
        op.create_index(
            "ix_orchestration_tasks_job_status",
            "orchestration_tasks",
            ["job_id", "status"],
        )
        op.create_index(
            "ix_orchestration_tasks_threat_model_status",
            "orchestration_tasks",
            ["threat_model_id", "status"],
        )

    if not _has_table("orchestration_events"):
        op.create_table(
            "orchestration_events",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column(
                "job_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("orchestration_jobs.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "task_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("orchestration_tasks.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "threat_model_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("threat_models.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("event_type", sa.String(40), nullable=False),
            sa.Column("level", sa.String(20), nullable=False, server_default="info"),
            sa.Column("message", sa.Text(), nullable=False),
            sa.Column(
                "payload",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=_jsonb_empty_object(),
            ),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
            sa.CheckConstraint(
                "event_type IN ('created','queued','started','tool_called','evidence_added','completed','failed','cancelled','note')",
                name="ck_orchestration_events_type",
            ),
            sa.CheckConstraint(
                "level IN ('debug','info','warning','error')",
                name="ck_orchestration_events_level",
            ),
        )
        op.create_index(
            "ix_orchestration_events_job_created",
            "orchestration_events",
            ["job_id", "created_at"],
        )
        op.create_index(
            "ix_orchestration_events_threat_model_created",
            "orchestration_events",
            ["threat_model_id", "created_at"],
        )


def downgrade() -> None:
    for table_name in (
        "orchestration_events",
        "orchestration_tasks",
        "orchestration_jobs",
    ):
        if _has_table(table_name):
            op.drop_table(table_name)
