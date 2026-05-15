"""Add threat agent orchestration runs.

Revision ID: 079
Revises: 078
Create Date: 2026-05-03
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "079"
down_revision = "078"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "threat_validation_runs" not in inspector.get_table_names():
        op.create_table(
            "threat_validation_runs",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
            sa.Column("tenant_key", sa.String(length=80), nullable=False),
            sa.Column("owner_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("threat_model_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("threat_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("application_review_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("orchestration_job_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="created"),
            sa.Column("conclusion", sa.String(length=40), nullable=True),
            sa.Column("question", sa.Text(), nullable=False),
            sa.Column("requested_tools", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="[]"),
            sa.Column("domain_agent_plan", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="[]"),
            sa.Column("domain_agent_results", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="[]"),
            sa.Column("evidence_refs", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="[]"),
            sa.Column("summary", sa.Text(), nullable=True),
            sa.Column("failure_reason", sa.Text(), nullable=True),
            sa.Column("agent_type", sa.String(length=40), nullable=False, server_default="threat_validation"),
            sa.Column("agent_version", sa.String(length=80), nullable=False),
            sa.Column("input_schema_version", sa.String(length=80), nullable=False),
            sa.Column("output_schema_version", sa.String(length=80), nullable=False),
            sa.Column("policy_version", sa.String(length=80), nullable=False),
            sa.Column("tool_harness_versions", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"),
            sa.Column("model_provider", sa.String(length=80), nullable=True),
            sa.Column("model_name", sa.String(length=160), nullable=True),
            sa.Column("prompt_version", sa.String(length=80), nullable=True),
            sa.Column("model_output_hash", sa.String(length=64), nullable=True),
            sa.Column("deterministic_fallback_used", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.CheckConstraint(
                "status IN ('created','running','completed','failed','blocked')",
                name="ck_threat_validation_runs_status",
            ),
            sa.CheckConstraint(
                "conclusion IS NULL OR conclusion IN "
                "('confirmed','not_supported','needs_human_review','more_evidence_required','failed')",
                name="ck_threat_validation_runs_conclusion",
            ),
            sa.CheckConstraint(
                "agent_type IN ('threat_validation','code_fix','iac_fix','configuration_fix')",
                name="ck_threat_validation_runs_agent_type",
            ),
            sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["threat_model_id"], ["threat_models.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["threat_id"], ["threats.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["application_review_id"], ["application_security_reviews.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["orchestration_job_id"], ["orchestration_jobs.id"], ondelete="SET NULL"),
        )
        op.create_index("ix_threat_validation_runs_threat_created", "threat_validation_runs", ["threat_id", "created_at"])
        op.create_index("ix_threat_validation_runs_tenant_created", "threat_validation_runs", ["tenant_key", "created_at"])
        op.create_index("ix_threat_validation_runs_review", "threat_validation_runs", ["application_review_id"])

    if "threat_remediation_runs" not in inspector.get_table_names():
        op.create_table(
            "threat_remediation_runs",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
            sa.Column("tenant_key", sa.String(length=80), nullable=False),
            sa.Column("owner_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("validation_run_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("threat_model_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("threat_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("application_review_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("orchestration_job_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("agent_type", sa.String(length=40), nullable=False),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="drafting"),
            sa.Column("fix_summary", sa.Text(), nullable=True),
            sa.Column("patch_preview", sa.Text(), nullable=True),
            sa.Column("ticket_draft", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"),
            sa.Column("pr_draft", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"),
            sa.Column("external_ticket_id", sa.String(length=240), nullable=True),
            sa.Column("external_ticket_url", sa.Text(), nullable=True),
            sa.Column("external_pr_url", sa.Text(), nullable=True),
            sa.Column("handoff_delivery_status", sa.String(length=32), nullable=False, server_default="recorded"),
            sa.Column("handoff_provider", sa.String(length=40), nullable=True),
            sa.Column("handoff_error", sa.Text(), nullable=True),
            sa.Column("handoff_idempotency_key", sa.String(length=240), nullable=True),
            sa.Column("evidence_refs", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="[]"),
            sa.Column("failure_reason", sa.Text(), nullable=True),
            sa.Column("agent_version", sa.String(length=80), nullable=False),
            sa.Column("input_schema_version", sa.String(length=80), nullable=False),
            sa.Column("output_schema_version", sa.String(length=80), nullable=False),
            sa.Column("policy_version", sa.String(length=80), nullable=False),
            sa.Column("tool_harness_versions", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"),
            sa.Column("model_provider", sa.String(length=80), nullable=True),
            sa.Column("model_name", sa.String(length=160), nullable=True),
            sa.Column("prompt_version", sa.String(length=80), nullable=True),
            sa.Column("model_output_hash", sa.String(length=64), nullable=True),
            sa.Column("deterministic_fallback_used", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.CheckConstraint(
                "status IN ('drafting','awaiting_confirmation','handoff_created','failed','cancelled')",
                name="ck_threat_remediation_runs_status",
            ),
            sa.CheckConstraint(
                "agent_type IN ('code_fix','iac_fix','configuration_fix')",
                name="ck_threat_remediation_runs_agent_type",
            ),
            sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["validation_run_id"], ["threat_validation_runs.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["threat_model_id"], ["threat_models.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["threat_id"], ["threats.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["application_review_id"], ["application_security_reviews.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["orchestration_job_id"], ["orchestration_jobs.id"], ondelete="SET NULL"),
        )
        op.create_index(
            "ix_threat_remediation_runs_validation_created",
            "threat_remediation_runs",
            ["validation_run_id", "created_at"],
        )
        op.create_index("ix_threat_remediation_runs_threat_created", "threat_remediation_runs", ["threat_id", "created_at"])
        op.create_index("ix_threat_remediation_runs_tenant_created", "threat_remediation_runs", ["tenant_key", "created_at"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "threat_remediation_runs" in inspector.get_table_names():
        op.drop_index("ix_threat_remediation_runs_tenant_created", table_name="threat_remediation_runs")
        op.drop_index("ix_threat_remediation_runs_threat_created", table_name="threat_remediation_runs")
        op.drop_index("ix_threat_remediation_runs_validation_created", table_name="threat_remediation_runs")
        op.drop_table("threat_remediation_runs")
    if "threat_validation_runs" in inspector.get_table_names():
        op.drop_index("ix_threat_validation_runs_review", table_name="threat_validation_runs")
        op.drop_index("ix_threat_validation_runs_tenant_created", table_name="threat_validation_runs")
        op.drop_index("ix_threat_validation_runs_threat_created", table_name="threat_validation_runs")
        op.drop_table("threat_validation_runs")
