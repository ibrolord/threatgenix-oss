"""Pilot readiness hardening.

Revision ID: 054
Revises: 053
Create Date: 2026-04-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "054"
down_revision = "053"
branch_labels = None
depends_on = None


def _inspector():
    return sa.inspect(op.get_bind())


def _has_column(table_name: str, column_name: str) -> bool:
    return any(
        column["name"] == column_name
        for column in _inspector().get_columns(table_name)
    )


def upgrade() -> None:
    bind = op.get_bind()

    if not _has_column("threat_models", "last_analyze_requested_at"):
        op.add_column(
            "threat_models",
            sa.Column("last_analyze_requested_at", sa.DateTime(timezone=True), nullable=True),
        )

    if bind.dialect.name == "postgresql":
        op.execute(
            """
            CREATE OR REPLACE FUNCTION prevent_threat_audit_log_mutation()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'threat_audit_logs is append-only';
            END;
            $$ LANGUAGE plpgsql;
            """
        )
        op.execute(
            """
            DROP TRIGGER IF EXISTS threat_audit_logs_append_only
            ON threat_audit_logs;
            """
        )
        op.execute(
            """
            CREATE TRIGGER threat_audit_logs_append_only
            BEFORE UPDATE OR DELETE ON threat_audit_logs
            FOR EACH ROW EXECUTE FUNCTION prevent_threat_audit_log_mutation();
            """
        )
        op.execute(
            """
            UPDATE compliance_mappings
            SET control_id = CASE control_name
                    WHEN 'Access Controls' THEN 'TG-B13-ACCESS'
                    WHEN 'Cyber Risk Management' THEN 'TG-B13-CYBER'
                    WHEN 'Vulnerability Management' THEN 'TG-B13-VULN'
                    WHEN 'Data Protection' THEN 'TG-B13-DATA'
                    WHEN 'Monitoring' THEN 'TG-B13-MON'
                    WHEN 'Business Continuity' THEN 'TG-B13-BCP'
                    WHEN 'Governance' THEN 'TG-B13-GOV'
                    WHEN 'Risk Management' THEN 'TG-B13-RISK'
                    WHEN 'Third Party Risk' THEN 'TG-B13-TPRM'
                    ELSE 'TG-B13-ALIGN'
                END,
                control_name = control_name || ' (ThreatGenix internal OSFI B-13 alignment)'
            WHERE framework = 'OSFI B-13'
              AND control_id LIKE 'B13-%';
            """
        )
    else:
        op.execute(
            """
            UPDATE compliance_mappings
            SET control_id = 'TG-B13-ALIGN',
                control_name = control_name || ' (ThreatGenix internal OSFI B-13 alignment)'
            WHERE framework = 'OSFI B-13'
              AND control_id LIKE 'B13-%';
            """
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS threat_audit_logs_append_only ON threat_audit_logs;"
        )
        op.execute("DROP FUNCTION IF EXISTS prevent_threat_audit_log_mutation();")
    if _has_column("threat_models", "last_analyze_requested_at"):
        op.drop_column("threat_models", "last_analyze_requested_at")
