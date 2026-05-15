"""Add DFD quality improvement columns: boundary_type, parent_boundary_id,
security_controls on nodes, tls_version/is_response/response_to_id/data_objects on edges.

Revision ID: 017
Revises: 015
Create Date: 2026-04-15
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "017"
down_revision = "015"
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(c["name"] == column for c in inspector.get_columns(table))


def upgrade() -> None:
    # --- trust_boundaries additions ---
    if not _has_column("trust_boundaries", "boundary_type"):
        op.add_column(
            "trust_boundaries",
            sa.Column("boundary_type", sa.String(50), nullable=True),
        )
    if not _has_column("trust_boundaries", "parent_boundary_id"):
        op.add_column(
            "trust_boundaries",
            sa.Column(
                "parent_boundary_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("trust_boundaries.id", ondelete="SET NULL"),
                nullable=True,
            ),
        )

    # --- dfd_nodes additions ---
    if not _has_column("dfd_nodes", "security_controls"):
        op.add_column(
            "dfd_nodes",
            sa.Column(
                "security_controls",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=True,
                server_default=sa.text("'[]'::jsonb"),
            ),
        )

    # --- dfd_edges additions ---
    if not _has_column("dfd_edges", "tls_version"):
        op.add_column(
            "dfd_edges",
            sa.Column("tls_version", sa.String(20), nullable=True),
        )
    if not _has_column("dfd_edges", "is_response"):
        op.add_column(
            "dfd_edges",
            sa.Column(
                "is_response",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
            ),
        )
    if not _has_column("dfd_edges", "response_to_id"):
        op.add_column(
            "dfd_edges",
            sa.Column(
                "response_to_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("dfd_edges.id", ondelete="SET NULL"),
                nullable=True,
            ),
        )
    if not _has_column("dfd_edges", "data_objects"):
        op.add_column(
            "dfd_edges",
            sa.Column(
                "data_objects",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=True,
                server_default=sa.text("'[]'::jsonb"),
            ),
        )


def downgrade() -> None:
    # --- dfd_edges removals ---
    if _has_column("dfd_edges", "data_objects"):
        op.drop_column("dfd_edges", "data_objects")
    if _has_column("dfd_edges", "response_to_id"):
        op.drop_column("dfd_edges", "response_to_id")
    if _has_column("dfd_edges", "is_response"):
        op.drop_column("dfd_edges", "is_response")
    if _has_column("dfd_edges", "tls_version"):
        op.drop_column("dfd_edges", "tls_version")

    # --- dfd_nodes removals ---
    if _has_column("dfd_nodes", "security_controls"):
        op.drop_column("dfd_nodes", "security_controls")

    # --- trust_boundaries removals ---
    if _has_column("trust_boundaries", "parent_boundary_id"):
        op.drop_column("trust_boundaries", "parent_boundary_id")
    if _has_column("trust_boundaries", "boundary_type"):
        op.drop_column("trust_boundaries", "boundary_type")
