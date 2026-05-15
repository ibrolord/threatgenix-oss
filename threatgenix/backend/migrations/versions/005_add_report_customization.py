"""Add report customization fields to threat_models table.

Revision ID: 005
Revises: 004
Create Date: 2026-04-14
"""

from alembic import op
import sqlalchemy as sa

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def _has_column(table_name: str, column_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def upgrade() -> None:
    if not _has_column("threat_models", "report_logo_base64"):
        op.add_column(
            "threat_models",
            sa.Column("report_logo_base64", sa.Text(), nullable=True),
        )
    if not _has_column("threat_models", "report_watermark_text"):
        op.add_column(
            "threat_models",
            sa.Column("report_watermark_text", sa.String(200), nullable=True),
        )
    if not _has_column("threat_models", "report_template"):
        op.add_column(
            "threat_models",
            sa.Column(
                "report_template",
                sa.String(50),
                nullable=False,
                server_default="default",
            ),
        )


def downgrade() -> None:
    op.drop_column("threat_models", "report_template")
    op.drop_column("threat_models", "report_watermark_text")
    op.drop_column("threat_models", "report_logo_base64")
