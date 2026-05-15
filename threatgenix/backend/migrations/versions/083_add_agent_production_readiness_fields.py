"""Add agent production-readiness fields.

Revision ID: 083
Revises: 082
Create Date: 2026-05-03
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "083"
down_revision = "082"
branch_labels = None
depends_on = None


def _columns(table_name: str) -> set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if table_name not in inspector.get_table_names():
        return set()
    return {column["name"] for column in inspector.get_columns(table_name)}


def upgrade() -> None:
    validation_columns = _columns("threat_validation_runs")
    if validation_columns and "domain_agent_results" not in validation_columns:
        op.add_column(
            "threat_validation_runs",
            sa.Column(
                "domain_agent_results",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'[]'::jsonb"),
            ),
        )

    remediation_columns = _columns("threat_remediation_runs")
    if remediation_columns and "handoff_delivery_status" not in remediation_columns:
        op.add_column(
            "threat_remediation_runs",
            sa.Column(
                "handoff_delivery_status",
                sa.String(length=32),
                nullable=False,
                server_default="recorded",
            ),
        )
    if remediation_columns and "handoff_provider" not in remediation_columns:
        op.add_column(
            "threat_remediation_runs",
            sa.Column("handoff_provider", sa.String(length=40), nullable=True),
        )
    if remediation_columns and "handoff_error" not in remediation_columns:
        op.add_column(
            "threat_remediation_runs",
            sa.Column("handoff_error", sa.Text(), nullable=True),
        )
    if remediation_columns and "handoff_idempotency_key" not in remediation_columns:
        op.add_column(
            "threat_remediation_runs",
            sa.Column("handoff_idempotency_key", sa.String(length=240), nullable=True),
        )


def downgrade() -> None:
    validation_columns = _columns("threat_validation_runs")
    if "domain_agent_results" in validation_columns:
        op.drop_column("threat_validation_runs", "domain_agent_results")

    remediation_columns = _columns("threat_remediation_runs")
    for column in (
        "handoff_idempotency_key",
        "handoff_error",
        "handoff_provider",
        "handoff_delivery_status",
    ):
        if column in remediation_columns:
            op.drop_column("threat_remediation_runs", column)
