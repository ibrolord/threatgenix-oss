"""Add deterministic STRIDE binding columns to scan_findings.

Revision ID: 049
Revises: 048
Create Date: 2026-04-27
"""

from alembic import op
import sqlalchemy as sa


revision = "049"
down_revision = "048"
branch_labels = None
depends_on = None


def _has_column(table_name: str, column_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def upgrade() -> None:
    if not _has_column("scan_findings", "binding_confidence"):
        op.add_column(
            "scan_findings",
            sa.Column("binding_confidence", sa.String(20), nullable=True),
        )
    if not _has_column("scan_findings", "false_positive"):
        op.add_column(
            "scan_findings",
            sa.Column(
                "false_positive",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
            ),
        )
    if not _has_column("scan_findings", "bound_stride_category"):
        op.add_column(
            "scan_findings",
            sa.Column("bound_stride_category", sa.String(50), nullable=True),
        )
    if not _has_column("scan_findings", "bound_threat_template"):
        op.add_column(
            "scan_findings",
            sa.Column("bound_threat_template", sa.String(200), nullable=True),
        )
    if not _has_column("scan_findings", "attack_technique"):
        op.add_column(
            "scan_findings",
            sa.Column("attack_technique", sa.String(50), nullable=True),
        )


def downgrade() -> None:
    for column in (
        "attack_technique",
        "bound_threat_template",
        "bound_stride_category",
        "false_positive",
        "binding_confidence",
    ):
        if _has_column("scan_findings", column):
            op.drop_column("scan_findings", column)
