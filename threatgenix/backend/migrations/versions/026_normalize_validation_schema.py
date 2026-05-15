"""Normalize the merged validation schema for ambiguously stamped databases.

Revision ID: 026
Revises: 025
Create Date: 2026-04-16
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "026"
down_revision = "025"
branch_labels = None
depends_on = None


def _has_column(table_name: str, column_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def upgrade() -> None:
    for column_name, comment in [
        ("dfd_component_templates", None),
        ("dfd_property_options", None),
        ("model_snapshots", None),
        ("review_records", None),
        ("control_library", None),
        (
            "iac_evidence",
            "Optional parsed Terraform / CloudFormation / Kubernetes IaC evidence attached to this threat model.",
        ),
        ("collaborators", "Threat-model collaborator roster with per-model role assignments."),
        ("assignments", "Shared analyst action items linked to reviews, threats, and DFD anchors."),
        ("notifications", "Per-model activity feed for reviews, assignments, and governance events."),
    ]:
        if not _has_column("threat_models", column_name):
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
    pass
