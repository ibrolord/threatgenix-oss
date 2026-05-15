"""Limit validation runners to current deterministic tools.

Revision ID: 041
Revises: 040
Create Date: 2026-04-26
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "041"
down_revision = "040"
branch_labels = None
depends_on = None

CURRENT_TOOLS = "'nuclei','semgrep','osv-scanner','trivy','checkov'"
CURRENT_TARGET_TYPES = "'url','repository_path','lockfile','container_image','iac_directory'"


def _has_table(table_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return table_name in inspector.get_table_names()


def _limit_constraints(table_name: str, tool_constraint: str, target_constraint: str) -> None:
    op.execute(
        f"UPDATE {table_name} SET tool_name = 'nuclei' "
        f"WHERE tool_name NOT IN ({CURRENT_TOOLS})"
    )
    op.execute(
        f"UPDATE {table_name} SET target_type = 'url' "
        f"WHERE target_type NOT IN ({CURRENT_TARGET_TYPES})"
    )
    op.execute(f"ALTER TABLE {table_name} DROP CONSTRAINT IF EXISTS {tool_constraint}")
    op.execute(
        f"ALTER TABLE {table_name} ADD CONSTRAINT {tool_constraint} "
        f"CHECK (tool_name IN ({CURRENT_TOOLS}))"
    )
    op.execute(f"ALTER TABLE {table_name} DROP CONSTRAINT IF EXISTS {target_constraint}")
    op.execute(
        f"ALTER TABLE {table_name} ADD CONSTRAINT {target_constraint} "
        f"CHECK (target_type IN ({CURRENT_TARGET_TYPES}))"
    )


def upgrade() -> None:
    if _has_table("scan_jobs"):
        _limit_constraints(
            "scan_jobs",
            "ck_scan_jobs_tool_name",
            "ck_scan_jobs_target_type",
        )
    if _has_table("validation_schedules"):
        _limit_constraints(
            "validation_schedules",
            "ck_validation_schedules_tool_name",
            "ck_validation_schedules_target_type",
        )


def downgrade() -> None:
    # The older expanded tool catalog is intentionally not restored. Historical rows
    # have already been normalized to the current runnable tool set.
    upgrade()
