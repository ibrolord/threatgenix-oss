"""Add explicit tenant ownership to threat models.

Revision ID: 056
Revises: 055
Create Date: 2026-04-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "056"
down_revision = "055"
branch_labels = None
depends_on = None


def _inspector():
    return sa.inspect(op.get_bind())


def _has_column(table_name: str, column_name: str) -> bool:
    return any(
        column["name"] == column_name
        for column in _inspector().get_columns(table_name)
    )


def _has_index(table_name: str, index_name: str) -> bool:
    return any(
        index["name"] == index_name
        for index in _inspector().get_indexes(table_name)
    )


def _has_foreign_key(table_name: str, constrained_column: str, referred_table: str) -> bool:
    return any(
        fk.get("referred_table") == referred_table
        and constrained_column in fk.get("constrained_columns", [])
        for fk in _inspector().get_foreign_keys(table_name)
    )


def upgrade() -> None:
    if not _has_column("threat_models", "organization_id"):
        op.add_column(
            "threat_models",
            sa.Column(
                "organization_id",
                postgresql.UUID(as_uuid=True),
                nullable=True,
                comment="Tenant workspace that owns this threat model.",
            ),
        )

    op.execute(
        """
        UPDATE threat_models AS threat_model
        SET organization_id = users.organization_id
        FROM users
        WHERE threat_model.owner_id = users.id
          AND threat_model.organization_id IS NULL
          AND users.organization_id IS NOT NULL;
        """
    )

    if not _has_index("threat_models", "ix_threat_models_organization_id"):
        op.create_index(
            "ix_threat_models_organization_id",
            "threat_models",
            ["organization_id"],
        )

    if not _has_foreign_key("threat_models", "organization_id", "organizations"):
        op.create_foreign_key(
            "fk_threat_models_organization_id",
            "threat_models",
            "organizations",
            ["organization_id"],
            ["id"],
        )


def downgrade() -> None:
    if _has_foreign_key("threat_models", "organization_id", "organizations"):
        op.drop_constraint(
            "fk_threat_models_organization_id",
            "threat_models",
            type_="foreignkey",
        )
    if _has_index("threat_models", "ix_threat_models_organization_id"):
        op.drop_index("ix_threat_models_organization_id", table_name="threat_models")
    if _has_column("threat_models", "organization_id"):
        op.drop_column("threat_models", "organization_id")
