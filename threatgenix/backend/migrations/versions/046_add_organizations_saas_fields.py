"""Add subscription_tier and is_active to organizations table.

Revision ID: 046
Revises: 045
Create Date: 2026-04-27
"""

from alembic import op
import sqlalchemy as sa

revision = "046"
down_revision = "045"
branch_labels = None
depends_on = None


def _has_column(table_name: str, column_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def upgrade() -> None:
    if not _has_column("organizations", "subscription_tier"):
        op.add_column(
            "organizations",
            sa.Column(
                "subscription_tier",
                sa.String(50),
                nullable=False,
                server_default="free",
                comment="Billing tier: free, pro, enterprise.",
            ),
        )
    if not _has_column("organizations", "is_active"):
        op.add_column(
            "organizations",
            sa.Column(
                "is_active",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("true"),
                comment="Whether this organization is active (billing/admin toggle).",
            ),
        )


def downgrade() -> None:
    if _has_column("organizations", "is_active"):
        op.drop_column("organizations", "is_active")
    if _has_column("organizations", "subscription_tier"):
        op.drop_column("organizations", "subscription_tier")
