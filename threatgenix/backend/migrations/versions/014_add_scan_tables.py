"""Add scan tables: scan_jobs, scan_findings, scan_threat_results, scan_authorizations.

Revision ID: 014
Revises: 013
Create Date: 2026-04-15
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "014"
down_revision = "013"
branch_labels = None
depends_on = None


def _has_table(table: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return table in inspector.get_table_names()


def upgrade() -> None:
    if not _has_table("scan_jobs"):
        op.create_table(
            "scan_jobs",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column("threat_model_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("threat_models.id", ondelete="CASCADE"), nullable=False),
            sa.Column("owner_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
            sa.Column("status", sa.String(20), server_default="pending", nullable=False),
            sa.Column("scan_type", sa.String(20), server_default="unauthenticated", nullable=False),
            sa.Column("scope", sa.String(20), server_default="external", nullable=False),
            sa.Column("targets", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
            sa.Column("nuclei_templates", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("finding_count", sa.Integer(), server_default="0", nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.CheckConstraint(
                "status IN ('pending','running','completed','failed','cancelled')",
                name="ck_scan_jobs_status",
            ),
            sa.CheckConstraint(
                "scan_type IN ('unauthenticated','authenticated')",
                name="ck_scan_jobs_scan_type",
            ),
            sa.CheckConstraint(
                "scope IN ('external','internal','full')",
                name="ck_scan_jobs_scope",
            ),
        )

    if not _has_table("scan_findings"):
        op.create_table(
            "scan_findings",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column("scan_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False),
            sa.Column("template_id", sa.String(200), nullable=False),
            sa.Column("template_name", sa.String(500), nullable=False),
            sa.Column("severity", sa.String(20), nullable=False),
            sa.Column("matched_at", sa.String(500), nullable=False),
            sa.Column("extracted_results", sa.Text(), nullable=True),
            sa.Column("cve_ids", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
            sa.Column("tags", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
            sa.Column("cvss_score", sa.Float(), nullable=True),
            sa.Column("raw_output", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.CheckConstraint(
                "severity IN ('critical','high','medium','low','info','unknown')",
                name="ck_scan_findings_severity",
            ),
        )

    if not _has_table("scan_threat_results"):
        op.create_table(
            "scan_threat_results",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column("scan_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False),
            sa.Column("threat_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("threats.id", ondelete="CASCADE"), nullable=False),
            sa.Column("scan_status", sa.String(20), nullable=False),
            sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
            sa.Column("cve_ids", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.CheckConstraint(
                "scan_status IN ('confirmed','mitigated','unverifiable','not_found')",
                name="ck_scan_threat_results_status",
            ),
        )

    if not _has_table("scan_authorizations"):
        op.create_table(
            "scan_authorizations",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column("scan_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, unique=True),
            sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
            sa.Column("acknowledged_text", sa.Text(), nullable=False),
            sa.Column("acknowledged_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.Column("ip_address", sa.String(50), nullable=True),
            sa.Column("targets_snapshot", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        )


def downgrade() -> None:
    for table in ["scan_threat_results", "scan_findings", "scan_authorizations", "scan_jobs"]:
        if _has_table(table):
            op.drop_table(table)
