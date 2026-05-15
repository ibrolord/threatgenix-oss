"""Add AI red-team validation tool.

Revision ID: 081
Revises: 080
Create Date: 2026-05-03
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "081"
down_revision = "080"
branch_labels = None
depends_on = None

SCAN_JOB_TOOLS = (
    "'nuclei','semgrep','osv-scanner','trivy','checkov','trufflehog',"
    "'ai-red-team','external-report','pentest-report'"
)
SCHEDULE_TOOLS = (
    "'nuclei','semgrep','osv-scanner','trivy','checkov','trufflehog','ai-red-team'"
)
TARGET_TYPES = (
    "'url','repository_path','lockfile','container_image','iac_directory','ai_system'"
)
PREVIOUS_SCAN_JOB_TOOLS = (
    "'nuclei','semgrep','osv-scanner','trivy','checkov','trufflehog',"
    "'external-report','pentest-report'"
)
PREVIOUS_SCHEDULE_TOOLS = (
    "'nuclei','semgrep','osv-scanner','trivy','checkov','trufflehog'"
)
PREVIOUS_TARGET_TYPES = (
    "'url','repository_path','lockfile','container_image','iac_directory'"
)


def _has_table(table_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return table_name in inspector.get_table_names()


def _refresh_check_constraint(
    table_name: str,
    constraint_name: str,
    column_name: str,
    allowed_values: str,
) -> None:
    op.execute(f"ALTER TABLE {table_name} DROP CONSTRAINT IF EXISTS {constraint_name}")
    op.execute(
        f"ALTER TABLE {table_name} ADD CONSTRAINT {constraint_name} "
        f"CHECK ({column_name} IN ({allowed_values}))"
    )


def upgrade() -> None:
    if _has_table("scan_jobs"):
        _refresh_check_constraint(
            "scan_jobs",
            "ck_scan_jobs_tool_name",
            "tool_name",
            SCAN_JOB_TOOLS,
        )
        _refresh_check_constraint(
            "scan_jobs",
            "ck_scan_jobs_target_type",
            "target_type",
            TARGET_TYPES,
        )
    if _has_table("validation_schedules"):
        _refresh_check_constraint(
            "validation_schedules",
            "ck_validation_schedules_tool_name",
            "tool_name",
            SCHEDULE_TOOLS,
        )
        _refresh_check_constraint(
            "validation_schedules",
            "ck_validation_schedules_target_type",
            "target_type",
            TARGET_TYPES,
        )


def downgrade() -> None:
    if _has_table("scan_jobs"):
        op.execute(
            "UPDATE scan_jobs SET tool_name = 'external-report' "
            "WHERE tool_name = 'ai-red-team'"
        )
        op.execute(
            "UPDATE scan_jobs SET target_type = 'repository_path' "
            "WHERE target_type = 'ai_system'"
        )
        _refresh_check_constraint(
            "scan_jobs",
            "ck_scan_jobs_tool_name",
            "tool_name",
            PREVIOUS_SCAN_JOB_TOOLS,
        )
        _refresh_check_constraint(
            "scan_jobs",
            "ck_scan_jobs_target_type",
            "target_type",
            PREVIOUS_TARGET_TYPES,
        )
    if _has_table("validation_schedules"):
        op.execute(
            "UPDATE validation_schedules SET tool_name = 'semgrep' "
            "WHERE tool_name = 'ai-red-team'"
        )
        op.execute(
            "UPDATE validation_schedules SET target_type = 'repository_path' "
            "WHERE target_type = 'ai_system'"
        )
        _refresh_check_constraint(
            "validation_schedules",
            "ck_validation_schedules_tool_name",
            "tool_name",
            PREVIOUS_SCHEDULE_TOOLS,
        )
        _refresh_check_constraint(
            "validation_schedules",
            "ck_validation_schedules_target_type",
            "target_type",
            PREVIOUS_TARGET_TYPES,
        )
