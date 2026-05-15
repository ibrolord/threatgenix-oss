"""add iac evidence column

Revision ID: 023
Revises: 022
Create Date: 2026-04-16
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "023"
down_revision = "022"
branch_labels = None
depends_on = None


def _column_exists(table_name: str, column_name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def upgrade() -> None:
    if not _column_exists("threat_models", "iac_evidence"):
        op.add_column(
            "threat_models",
            sa.Column(
                "iac_evidence",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=True,
                comment="Optional parsed Terraform / CloudFormation / Kubernetes IaC evidence attached to this threat model.",
            ),
        )


def downgrade() -> None:
    if _column_exists("threat_models", "iac_evidence"):
        op.drop_column("threat_models", "iac_evidence")
