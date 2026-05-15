"""Add validation case workflow state.

Revision ID: 043
Revises: 042
Create Date: 2026-04-26
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "043"
down_revision = "042"
branch_labels = None
depends_on = None


def _has_table(table_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return table_name in inspector.get_table_names()


def upgrade() -> None:
    if not _has_table("validation_case_states"):
        op.create_table(
            "validation_case_states",
            sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("threat_model_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("case_key", sa.String(length=120), nullable=False),
            sa.Column("case_type", sa.String(length=40), nullable=False),
            sa.Column("workflow_status", sa.String(length=30), nullable=False, server_default="open"),
            sa.Column("workflow_priority", sa.String(length=2), nullable=True),
            sa.Column("owner_label", sa.String(length=200), nullable=True),
            sa.Column("due_date", sa.Date(), nullable=True),
            sa.Column("analyst_note", sa.Text(), nullable=True),
            sa.Column("last_decision", sa.Text(), nullable=True),
            sa.Column("created_by_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("updated_by_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.CheckConstraint(
                "case_type IN ('threat','unbound_finding')",
                name="ck_validation_case_states_case_type",
            ),
            sa.CheckConstraint(
                "workflow_status IN ('open','investigating','mitigated','accepted','dismissed','refuted')",
                name="ck_validation_case_states_workflow_status",
            ),
            sa.CheckConstraint(
                "workflow_priority IN ('P1','P2','P3') OR workflow_priority IS NULL",
                name="ck_validation_case_states_priority",
            ),
            sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["threat_model_id"], ["threat_models.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["updated_by_id"], ["users.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("threat_model_id", "case_key", name="uq_validation_case_state_model_case"),
        )
        op.create_index(
            "ix_validation_case_states_threat_model_status",
            "validation_case_states",
            ["threat_model_id", "workflow_status"],
        )

    if not _has_table("validation_case_events"):
        op.create_table(
            "validation_case_events",
            sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("case_state_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("threat_model_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("action", sa.String(length=30), nullable=False),
            sa.Column("changes", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("note", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.CheckConstraint(
                "action IN ('created','updated')",
                name="ck_validation_case_events_action",
            ),
            sa.ForeignKeyConstraint(["actor_id"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["case_state_id"], ["validation_case_states.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["threat_model_id"], ["threat_models.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_validation_case_events_case_created",
            "validation_case_events",
            ["case_state_id", "created_at"],
        )
        op.create_index(
            "ix_validation_case_events_threat_model",
            "validation_case_events",
            ["threat_model_id"],
        )


def downgrade() -> None:
    if _has_table("validation_case_events"):
        op.drop_index("ix_validation_case_events_threat_model", table_name="validation_case_events")
        op.drop_index("ix_validation_case_events_case_created", table_name="validation_case_events")
        op.drop_table("validation_case_events")
    if _has_table("validation_case_states"):
        op.drop_index("ix_validation_case_states_threat_model_status", table_name="validation_case_states")
        op.drop_table("validation_case_states")
