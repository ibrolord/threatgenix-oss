"""add collaboration columns

Revision ID: 024
Revises: 023
Create Date: 2026-04-16
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "024"
down_revision = "023"
branch_labels = None
depends_on = None


def _column_exists(table_name: str, column_name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def upgrade() -> None:
    for column_name, comment in [
        ("collaborators", "Threat-model collaborator roster with per-model role assignments."),
        ("assignments", "Shared analyst action items linked to reviews, threats, and DFD anchors."),
        ("notifications", "Per-model activity feed for reviews, assignments, and governance events."),
    ]:
        if not _column_exists("threat_models", column_name):
            op.add_column(
                "threat_models",
                sa.Column(
                    column_name,
                    postgresql.JSONB(astext_type=sa.Text()),
                    nullable=True,
                    comment=comment,
                ),
            )


def downgrade() -> None:
    for column_name in ["notifications", "assignments", "collaborators"]:
        if _column_exists("threat_models", column_name):
            op.drop_column("threat_models", column_name)
