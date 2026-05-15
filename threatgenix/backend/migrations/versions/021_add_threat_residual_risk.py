"""Add control effectiveness and residual risk fields to threats.

Revision ID: 021
Revises: 018
Create Date: 2026-04-16
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "021"
down_revision = "018"
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(c["name"] == column for c in inspector.get_columns(table))


def _has_constraint(table: str, name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(c["name"] == name for c in inspector.get_check_constraints(table))


def upgrade() -> None:
    if not _has_column("threats", "control_effectiveness"):
        op.add_column(
            "threats",
            sa.Column(
                "control_effectiveness",
                sa.String(20),
                nullable=False,
                server_default="none",
            ),
        )

    if not _has_column("threats", "residual_risk_level"):
        op.add_column(
            "threats",
            sa.Column("residual_risk_level", sa.String(20), nullable=True),
        )

    op.execute("UPDATE threats SET control_effectiveness = COALESCE(control_effectiveness, 'none')")
    op.execute(
        """
        UPDATE threats
        SET residual_risk_level = CASE severity
            WHEN 'Critical' THEN 'Critical'
            WHEN 'High' THEN 'High'
            WHEN 'Medium' THEN 'Medium'
            WHEN 'Low' THEN 'Low'
            ELSE 'Medium'
        END
        WHERE residual_risk_level IS NULL
        """
    )

    if not _has_constraint("threats", "ck_threats_control_effectiveness"):
        op.create_check_constraint(
            "ck_threats_control_effectiveness",
            "threats",
            "control_effectiveness IN ('none', 'partial', 'substantial', 'full')",
        )

    if not _has_constraint("threats", "ck_threats_residual_risk_level"):
        op.create_check_constraint(
            "ck_threats_residual_risk_level",
            "threats",
            "residual_risk_level IN ('Critical', 'High', 'Medium', 'Low', 'Negligible')",
        )


def downgrade() -> None:
    if _has_constraint("threats", "ck_threats_residual_risk_level"):
        op.drop_constraint("ck_threats_residual_risk_level", "threats", type_="check")
    if _has_constraint("threats", "ck_threats_control_effectiveness"):
        op.drop_constraint("ck_threats_control_effectiveness", "threats", type_="check")
    if _has_column("threats", "residual_risk_level"):
        op.drop_column("threats", "residual_risk_level")
    if _has_column("threats", "control_effectiveness"):
        op.drop_column("threats", "control_effectiveness")
