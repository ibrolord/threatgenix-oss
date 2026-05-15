"""Add persisted geometry to trust boundaries.

Revision ID: 007
Revises: 006
Create Date: 2026-04-15
"""

from alembic import op
import sqlalchemy as sa

revision = "007"
down_revision = "006"
branch_labels = None
depends_on = None

BOUNDARY_PADDING = 20.0
NODE_WIDTH = 180.0
NODE_HEIGHT = 64.0
DEFAULT_BOUNDARY_WIDTH = 280.0
DEFAULT_BOUNDARY_HEIGHT = 180.0


def _has_column(table_name: str, column_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def upgrade() -> None:
    if not _has_column("trust_boundaries", "position_x"):
        op.add_column(
            "trust_boundaries",
            sa.Column("position_x", sa.Float(), nullable=False, server_default="0"),
        )
    if not _has_column("trust_boundaries", "position_y"):
        op.add_column(
            "trust_boundaries",
            sa.Column("position_y", sa.Float(), nullable=False, server_default="0"),
        )
    if not _has_column("trust_boundaries", "width"):
        op.add_column(
            "trust_boundaries",
            sa.Column("width", sa.Float(), nullable=False, server_default=str(DEFAULT_BOUNDARY_WIDTH)),
        )
    if not _has_column("trust_boundaries", "height"):
        op.add_column(
            "trust_boundaries",
            sa.Column("height", sa.Float(), nullable=False, server_default=str(DEFAULT_BOUNDARY_HEIGHT)),
        )

    conn = op.get_bind()
    boundary_rows = conn.execute(
        sa.text("SELECT id, node_ids FROM trust_boundaries")
    ).mappings().all()
    node_rows = conn.execute(
        sa.text("SELECT id, position_x, position_y FROM dfd_nodes")
    ).mappings().all()
    node_position_by_id = {
        row["id"]: (float(row["position_x"]), float(row["position_y"])) for row in node_rows
    }

    for boundary_row in boundary_rows:
        node_ids = list(boundary_row["node_ids"] or [])
        positions = [
            node_position_by_id[node_id]
            for node_id in node_ids
            if node_id in node_position_by_id
        ]

        if positions:
            min_x = min(position_x for position_x, _ in positions)
            min_y = min(position_y for _, position_y in positions)
            max_x = max(position_x + NODE_WIDTH for position_x, _ in positions)
            max_y = max(position_y + NODE_HEIGHT for _, position_y in positions)
            position_x = min_x - BOUNDARY_PADDING
            position_y = min_y - BOUNDARY_PADDING
            width = max_x - min_x + BOUNDARY_PADDING * 2
            height = max_y - min_y + BOUNDARY_PADDING * 2
        else:
            position_x = 0.0
            position_y = 0.0
            width = DEFAULT_BOUNDARY_WIDTH
            height = DEFAULT_BOUNDARY_HEIGHT

        conn.execute(
            sa.text(
                "UPDATE trust_boundaries "
                "SET position_x = :position_x, position_y = :position_y, width = :width, height = :height "
                "WHERE id = :boundary_id"
            ),
            {
                "boundary_id": boundary_row["id"],
                "position_x": position_x,
                "position_y": position_y,
                "width": width,
                "height": height,
            },
        )


def downgrade() -> None:
    if _has_column("trust_boundaries", "height"):
        op.drop_column("trust_boundaries", "height")
    if _has_column("trust_boundaries", "width"):
        op.drop_column("trust_boundaries", "width")
    if _has_column("trust_boundaries", "position_y"):
        op.drop_column("trust_boundaries", "position_y")
    if _has_column("trust_boundaries", "position_x"):
        op.drop_column("trust_boundaries", "position_x")
