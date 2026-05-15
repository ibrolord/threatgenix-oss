"""Weeks 5-8 schema updates: copilot snapshot, compliance multi-framework,
threat audit logs, manual threats, compliance field renames.

Revision ID: 003
Revises: 002
Create Date: 2026-04-03
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def _has_column(table_name: str, column_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def upgrade() -> None:
    # 1. Add last_analyzed_threats JSONB column for copilot diff snapshots
    if not _has_column("threat_models", "last_analyzed_threats"):
        op.add_column(
            "threat_models",
            sa.Column("last_analyzed_threats", JSONB, nullable=True),
        )

    # 2. Compliance mappings: add framework + generic field names
    #    (create_all may have added these already — use IF NOT EXISTS via raw SQL)
    conn = op.get_bind()

    # Add framework column if missing
    result = conn.execute(sa.text(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name = 'compliance_mappings' AND column_name = 'framework'"
    ))
    if result.fetchone() is None:
        op.add_column(
            "compliance_mappings",
            sa.Column("framework", sa.String(50), nullable=False, server_default="NIST 800-53"),
        )

    # Add control_id column if missing
    result = conn.execute(sa.text(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name = 'compliance_mappings' AND column_name = 'control_id'"
    ))
    if result.fetchone() is None:
        op.add_column(
            "compliance_mappings",
            sa.Column("control_id", sa.String(20), nullable=False, server_default=""),
        )

    # Add control_name column if missing
    result = conn.execute(sa.text(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name = 'compliance_mappings' AND column_name = 'control_name'"
    ))
    if result.fetchone() is None:
        op.add_column(
            "compliance_mappings",
            sa.Column("control_name", sa.String(255), nullable=False, server_default=""),
        )

    # Copy data from old columns to new if old columns exist
    result = conn.execute(sa.text(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name = 'compliance_mappings' AND column_name = 'nist_control_id'"
    ))
    if result.fetchone() is not None:
        conn.execute(sa.text(
            "UPDATE compliance_mappings SET control_id = nist_control_id, "
            "control_name = nist_control_name WHERE control_id = '' OR control_id IS NULL"
        ))
        op.drop_column("compliance_mappings", "nist_control_id")
        op.drop_column("compliance_mappings", "nist_control_name")

    # Update unique constraint to include framework
    # Use IF EXISTS to avoid aborting the transaction on missing constraints
    conn.execute(sa.text(
        "ALTER TABLE compliance_mappings DROP CONSTRAINT IF EXISTS "
        "compliance_mappings_stride_category_threat_subtype_nist_con_key"
    ))
    conn.execute(sa.text(
        "ALTER TABLE compliance_mappings DROP CONSTRAINT IF EXISTS uq_compliance_mapping"
    ))

    # Check if constraint already exists with the right columns before creating
    result = conn.execute(sa.text(
        "SELECT 1 FROM information_schema.table_constraints "
        "WHERE table_name = 'compliance_mappings' AND constraint_name = 'uq_compliance_mapping'"
    ))
    if result.fetchone() is None:
        op.create_unique_constraint(
            "uq_compliance_mapping",
            "compliance_mappings",
            ["stride_category", "threat_subtype", "framework", "control_id"],
        )

    # 3. Update threats source check constraint to allow 'Manual'
    conn.execute(sa.text(
        "ALTER TABLE threats DROP CONSTRAINT IF EXISTS ck_threats_source"
    ))

    op.create_check_constraint(
        "ck_threats_source",
        "threats",
        "source IN ('Rules', 'AI', 'AI+Rules', 'Manual')",
    )

    # 4. Create threat_audit_logs table if not exists
    result = conn.execute(sa.text(
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_name = 'threat_audit_logs'"
    ))
    if result.fetchone() is None:
        op.create_table(
            "threat_audit_logs",
            sa.Column("id", sa.dialects.postgresql.UUID(), primary_key=True),
            sa.Column("threat_id", sa.dialects.postgresql.UUID(), sa.ForeignKey("threats.id", ondelete="CASCADE"), nullable=False),
            sa.Column("threat_model_id", sa.dialects.postgresql.UUID(), sa.ForeignKey("threat_models.id", ondelete="CASCADE"), nullable=False),
            sa.Column("user_id", sa.dialects.postgresql.UUID(), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("action", sa.String(30), nullable=False),
            sa.Column("old_status", sa.String(20), nullable=True),
            sa.Column("new_status", sa.String(20), nullable=False),
            sa.Column("reason", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
        op.create_index(
            "ix_audit_threat_created",
            "threat_audit_logs",
            ["threat_id", "created_at"],
        )


def downgrade() -> None:
    op.drop_table("threat_audit_logs")
    op.drop_constraint("ck_threats_source", "threats")
    op.create_check_constraint(
        "ck_threats_source",
        "threats",
        "source IN ('Rules', 'AI', 'AI+Rules')",
    )
    op.drop_constraint("uq_compliance_mapping", "compliance_mappings")
    op.drop_column("compliance_mappings", "control_name")
    op.drop_column("compliance_mappings", "control_id")
    op.drop_column("compliance_mappings", "framework")
    op.add_column("compliance_mappings", sa.Column("nist_control_id", sa.String(20), nullable=False))
    op.add_column("compliance_mappings", sa.Column("nist_control_name", sa.String(255), nullable=False))
    op.drop_column("threat_models", "last_analyzed_threats")
