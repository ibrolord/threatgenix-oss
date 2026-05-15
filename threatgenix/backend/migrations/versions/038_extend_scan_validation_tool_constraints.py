"""Extend scan validation tool constraints.

Revision ID: 038
Revises: 037
Create Date: 2026-04-26
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "038"
down_revision = "037"
branch_labels = None
depends_on = None


def _has_table(table_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return table_name in inspector.get_table_names()


def upgrade() -> None:
    if not _has_table("scan_jobs"):
        return

    op.execute("ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS ck_scan_jobs_tool_name")
    op.execute(
        "ALTER TABLE scan_jobs ADD CONSTRAINT ck_scan_jobs_tool_name "
        "CHECK (tool_name IN ('nuclei','semgrep','osv-scanner','trivy','checkov'))"
    )
    op.execute("ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS ck_scan_jobs_target_type")
    op.execute(
        "ALTER TABLE scan_jobs ADD CONSTRAINT ck_scan_jobs_target_type "
        "CHECK (target_type IN ('url','repository_path','lockfile','container_image','iac_directory'))"
    )


def downgrade() -> None:
    if not _has_table("scan_jobs"):
        return

    op.execute("ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS ck_scan_jobs_target_type")
    op.execute(
        "ALTER TABLE scan_jobs ADD CONSTRAINT ck_scan_jobs_target_type "
        "CHECK (target_type IN ('url','repository_path','lockfile','container_image','iac_directory'))"
    )
    op.execute("ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS ck_scan_jobs_tool_name")
    op.execute(
        "ALTER TABLE scan_jobs ADD CONSTRAINT ck_scan_jobs_tool_name "
        "CHECK (tool_name IN ('nuclei','semgrep','osv-scanner','trivy','checkov'))"
    )
