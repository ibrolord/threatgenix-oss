"""Add validation tool dispatch fields to scan jobs.

Revision ID: 036
Revises: 035
Create Date: 2026-04-25
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "036"
down_revision = "035"
branch_labels = None
depends_on = None


def _has_table(table_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return table_name in inspector.get_table_names()


def _has_column(table_name: str, column_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def upgrade() -> None:
    if not _has_table("scan_jobs"):
        return

    if not _has_column("scan_jobs", "tool_name"):
        op.add_column(
            "scan_jobs",
            sa.Column("tool_name", sa.String(50), server_default="nuclei", nullable=False),
        )

    if not _has_column("scan_jobs", "target_type"):
        op.add_column(
            "scan_jobs",
            sa.Column("target_type", sa.String(50), server_default="url", nullable=False),
        )

    op.execute("UPDATE scan_jobs SET tool_name = 'nuclei' WHERE tool_name IS NULL OR tool_name = ''")
    op.execute("UPDATE scan_jobs SET target_type = 'url' WHERE target_type IS NULL OR target_type = ''")
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
    op.execute("ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS ck_scan_jobs_tool_name")
    if _has_column("scan_jobs", "target_type"):
        op.drop_column("scan_jobs", "target_type")
    if _has_column("scan_jobs", "tool_name"):
        op.drop_column("scan_jobs", "tool_name")
