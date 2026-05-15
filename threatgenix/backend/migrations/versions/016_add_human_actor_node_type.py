"""Expand DFD node_type CHECK constraint to include human_actor.

Revision ID: 016
Revises: 015
Create Date: 2026-04-15
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "016"
down_revision = "015"
branch_labels = None
depends_on = None

_ALL_TYPES = (
    "'process','data_store','external_entity','human_actor',"
    "'iam_role','managed_service','api_gateway','container','serverless'"
)
_PREVIOUS_TYPES = (
    "'process','data_store','external_entity',"
    "'iam_role','managed_service','api_gateway','container','serverless'"
)
_CONSTRAINT = "ck_dfd_nodes_node_type"


def _has_constraint(table: str, name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(c["name"] == name for c in inspector.get_check_constraints(table))


def upgrade() -> None:
    if _has_constraint("dfd_nodes", _CONSTRAINT):
        op.drop_constraint(_CONSTRAINT, "dfd_nodes", type_="check")
    op.create_check_constraint(
        _CONSTRAINT,
        "dfd_nodes",
        f"node_type IN ({_ALL_TYPES})",
    )


def downgrade() -> None:
    # WARNING: downgrade will fail if any rows use human_actor.
    if _has_constraint("dfd_nodes", _CONSTRAINT):
        op.drop_constraint(_CONSTRAINT, "dfd_nodes", type_="check")
    op.create_check_constraint(
        _CONSTRAINT,
        "dfd_nodes",
        f"node_type IN ({_PREVIOUS_TYPES})",
    )
