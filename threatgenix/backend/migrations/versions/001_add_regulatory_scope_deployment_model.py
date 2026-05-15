"""Add regulatory_scope and deployment_model columns to threat_models.

Revision ID: 001
Revises: None
Create Date: 2026-04-03
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def _has_column(table_name: str, column_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def upgrade() -> None:
    if not _has_column("threat_models", "regulatory_scope"):
        op.add_column(
            "threat_models",
            sa.Column(
                "regulatory_scope",
                ARRAY(sa.String(50)),
                nullable=True,
                comment="Selected regulatory frameworks: OSFI B-13, PCI DSS, PIPEDA, FINTRAC, NIST, ISO 27001",
            ),
        )
    if not _has_column("threat_models", "deployment_model"):
        op.add_column(
            "threat_models",
            sa.Column(
                "deployment_model",
                sa.String(50),
                nullable=True,
                comment="Deployment model: on-prem, cloud, hybrid",
            ),
        )


def downgrade() -> None:
    op.drop_column("threat_models", "deployment_model")
    op.drop_column("threat_models", "regulatory_scope")
