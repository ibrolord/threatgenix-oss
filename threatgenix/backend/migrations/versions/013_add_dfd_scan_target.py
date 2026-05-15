"""Add scan_target_url and scan_target_ports to dfd_nodes.

Revision ID: 013
Revises: 012
"""
from alembic import op
import sqlalchemy as sa

revision = "013"
down_revision = "012"
branch_labels = None
depends_on = None

_TABLE = "dfd_nodes"

def _has_column(table, column):
    inspector = sa.inspect(op.get_bind())
    return any(c["name"] == column for c in inspector.get_columns(table))

def upgrade():
    if not _has_column(_TABLE, "scan_target_url"):
        op.add_column(_TABLE, sa.Column("scan_target_url", sa.String(500), nullable=True))
    if not _has_column(_TABLE, "scan_target_ports"):
        op.add_column(_TABLE, sa.Column("scan_target_ports", sa.String(200), nullable=True))

def downgrade():
    if _has_column(_TABLE, "scan_target_url"):
        op.drop_column(_TABLE, "scan_target_url")
    if _has_column(_TABLE, "scan_target_ports"):
        op.drop_column(_TABLE, "scan_target_ports")
