"""Add blocked orchestration job and event statuses.

Revision ID: 055
Revises: 054
Create Date: 2026-04-29
"""

from __future__ import annotations

from alembic import op

revision = "055"
down_revision = "054"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(
        "ck_orchestration_jobs_status",
        "orchestration_jobs",
        type_="check",
    )
    op.create_check_constraint(
        "ck_orchestration_jobs_status",
        "orchestration_jobs",
        "status IN ('pending','running','completed','failed','cancelled','blocked')",
    )
    op.drop_constraint(
        "ck_orchestration_events_type",
        "orchestration_events",
        type_="check",
    )
    op.create_check_constraint(
        "ck_orchestration_events_type",
        "orchestration_events",
        "event_type IN ('created','queued','started','tool_called','evidence_added','completed','failed','cancelled','blocked','note')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_orchestration_events_type",
        "orchestration_events",
        type_="check",
    )
    op.create_check_constraint(
        "ck_orchestration_events_type",
        "orchestration_events",
        "event_type IN ('created','queued','started','tool_called','evidence_added','completed','failed','cancelled','note')",
    )
    op.drop_constraint(
        "ck_orchestration_jobs_status",
        "orchestration_jobs",
        type_="check",
    )
    op.create_check_constraint(
        "ck_orchestration_jobs_status",
        "orchestration_jobs",
        "status IN ('pending','running','completed','failed','cancelled')",
    )
