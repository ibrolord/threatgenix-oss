"""Add analyst attestation and review scheduling fields to threat_models.

Revision ID: 045
Revises: 044
Create Date: 2026-04-27
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "045"
down_revision = "044"


def upgrade() -> None:
    op.add_column(
        "threat_models",
        sa.Column("analyst_name", sa.String(255), nullable=True),
    )
    op.add_column(
        "threat_models",
        sa.Column("analyst_attestation", sa.Text, nullable=True),
    )
    op.add_column(
        "threat_models",
        sa.Column("next_review_date", sa.Date, nullable=True),
    )
    op.add_column(
        "threat_models",
        sa.Column("out_of_scope_statement", sa.Text, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("threat_models", "out_of_scope_statement")
    op.drop_column("threat_models", "next_review_date")
    op.drop_column("threat_models", "analyst_attestation")
    op.drop_column("threat_models", "analyst_name")
