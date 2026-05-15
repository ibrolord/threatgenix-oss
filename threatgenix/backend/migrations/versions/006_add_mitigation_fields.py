"""Add mitigation tracking fields to threats table.

Revision ID: 006
Revises: 005
Create Date: 2026-04-14
"""

from alembic import op
import sqlalchemy as sa

revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def _has_column(table_name: str, column_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def upgrade() -> None:
    # Add mitigation columns
    if not _has_column("threats", "mitigation_plan"):
        op.add_column("threats", sa.Column("mitigation_plan", sa.Text(), nullable=True))
    if not _has_column("threats", "mitigation_owner"):
        op.add_column(
            "threats", sa.Column("mitigation_owner", sa.String(200), nullable=True)
        )
    if not _has_column("threats", "due_date"):
        op.add_column("threats", sa.Column("due_date", sa.Date(), nullable=True))
    if not _has_column("threats", "mitigation_notes"):
        op.add_column("threats", sa.Column("mitigation_notes", sa.Text(), nullable=True))
    if not _has_column("threats", "closed_at"):
        op.add_column(
            "threats",
            sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        )

    # Replace status CHECK constraint to include new statuses
    op.execute(
        sa.text("ALTER TABLE threats DROP CONSTRAINT IF EXISTS ck_threats_status")
    )
    op.execute(
        sa.text(
            "ALTER TABLE threats ADD CONSTRAINT ck_threats_status "
            "CHECK (status IN ('Open', 'In Progress', 'Mitigated', 'Accepted', 'Dismissed'))"
        )
    )


def downgrade() -> None:
    # Restore original status CHECK constraint
    op.drop_constraint("ck_threats_status", "threats", type_="check")
    op.create_check_constraint(
        "ck_threats_status",
        "threats",
        "status IN ('Open', 'Accepted', 'Dismissed')",
    )

    # Drop mitigation columns
    op.drop_column("threats", "closed_at")
    op.drop_column("threats", "mitigation_notes")
    op.drop_column("threats", "due_date")
    op.drop_column("threats", "mitigation_owner")
    op.drop_column("threats", "mitigation_plan")
