"""Add import-only external evidence sources.

Revision ID: 042
Revises: 041
Create Date: 2026-04-26
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "042"
down_revision = "041"
branch_labels = None
depends_on = None

RUNNABLE_TOOLS = "'nuclei','semgrep','osv-scanner','trivy','checkov'"
# Include legacy tool names (zap-baseline, promptfoo) that may exist in deployed databases
SCAN_JOB_TOOLS = f"{RUNNABLE_TOOLS},'external-report','pentest-report','zap-baseline','promptfoo'"


def _has_table(table_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return table_name in inspector.get_table_names()


def upgrade() -> None:
    if not _has_table("scan_jobs"):
        return
    op.execute("ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS ck_scan_jobs_tool_name")
    op.execute(
        "ALTER TABLE scan_jobs ADD CONSTRAINT ck_scan_jobs_tool_name "
        f"CHECK (tool_name IN ({SCAN_JOB_TOOLS}))"
    )


def downgrade() -> None:
    if not _has_table("scan_jobs"):
        return
    op.execute("UPDATE scan_jobs SET tool_name = 'nuclei' WHERE tool_name NOT IN ({})".format(RUNNABLE_TOOLS))
    op.execute("ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS ck_scan_jobs_tool_name")
    op.execute(
        "ALTER TABLE scan_jobs ADD CONSTRAINT ck_scan_jobs_tool_name "
        f"CHECK (tool_name IN ({RUNNABLE_TOOLS}))"
    )
