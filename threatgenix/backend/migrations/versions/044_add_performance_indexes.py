"""Add performance indexes for threats, DFD nodes, edges, trust boundaries.

Revision ID: 044
Revises: 043
Create Date: 2026-04-27
"""

from __future__ import annotations

from alembic import op

revision = "044"
down_revision = "043"


def upgrade() -> None:
    # Threats — every query filters on threat_model_id
    op.create_index(
        "ix_threats_threat_model_id",
        "threats",
        ["threat_model_id"],
        if_not_exists=True,
    )
    op.create_index(
        "ix_threats_model_status",
        "threats",
        ["threat_model_id", "status"],
        if_not_exists=True,
    )
    op.create_index(
        "ix_threats_model_display_id",
        "threats",
        ["threat_model_id", "display_id"],
        if_not_exists=True,
    )

    # DFD tables — every load filters on threat_model_id
    op.create_index(
        "ix_dfd_nodes_threat_model_id",
        "dfd_nodes",
        ["threat_model_id"],
        if_not_exists=True,
    )
    op.create_index(
        "ix_dfd_edges_threat_model_id",
        "dfd_edges",
        ["threat_model_id"],
        if_not_exists=True,
    )
    op.create_index(
        "ix_trust_boundaries_threat_model_id",
        "trust_boundaries",
        ["threat_model_id"],
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_index("ix_trust_boundaries_threat_model_id", table_name="trust_boundaries")
    op.drop_index("ix_dfd_edges_threat_model_id", table_name="dfd_edges")
    op.drop_index("ix_dfd_nodes_threat_model_id", table_name="dfd_nodes")
    op.drop_index("ix_threats_model_display_id", table_name="threats")
    op.drop_index("ix_threats_model_status", table_name="threats")
    op.drop_index("ix_threats_threat_model_id", table_name="threats")
