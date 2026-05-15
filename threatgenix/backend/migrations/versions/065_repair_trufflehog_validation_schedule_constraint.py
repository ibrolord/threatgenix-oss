"""Repair TruffleHog validation schedule constraint.

Revision ID: 065
Revises: 064
Create Date: 2026-04-30
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "065"
down_revision = "064"
branch_labels = None
depends_on = None

SCAN_JOB_TOOLS = (
    "'nuclei','semgrep','osv-scanner','trivy','checkov',"
    "'trufflehog','external-report','pentest-report'"
)
SCHEDULE_TOOLS = "'nuclei','semgrep','osv-scanner','trivy','checkov','trufflehog'"


def _has_table(table_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return table_name in inspector.get_table_names()


def _refresh_tool_constraint(table_name: str, constraint_name: str, tools: str) -> None:
    op.execute(f"ALTER TABLE {table_name} DROP CONSTRAINT IF EXISTS {constraint_name}")
    op.execute(
        f"ALTER TABLE {table_name} ADD CONSTRAINT {constraint_name} "
        f"CHECK (tool_name IN ({tools}))"
    )


def upgrade() -> None:
    if _has_table("scan_jobs"):
        _refresh_tool_constraint(
            "scan_jobs",
            "ck_scan_jobs_tool_name",
            SCAN_JOB_TOOLS,
        )
    if _has_table("validation_schedules"):
        _refresh_tool_constraint(
            "validation_schedules",
            "ck_validation_schedules_tool_name",
            SCHEDULE_TOOLS,
        )


def downgrade() -> None:
    if _has_table("scan_jobs"):
        op.execute(
            "UPDATE scan_jobs SET tool_name = 'external-report' "
            "WHERE tool_name = 'trufflehog'"
        )
        _refresh_tool_constraint(
            "scan_jobs",
            "ck_scan_jobs_tool_name",
            "'nuclei','semgrep','osv-scanner','trivy','checkov',"
            "'external-report','pentest-report'",
        )
    if _has_table("validation_schedules"):
        op.execute(
            "UPDATE validation_schedules SET tool_name = 'semgrep' "
            "WHERE tool_name = 'trufflehog'"
        )
        _refresh_tool_constraint(
            "validation_schedules",
            "ck_validation_schedules_tool_name",
            "'nuclei','semgrep','osv-scanner','trivy','checkov'",
        )
