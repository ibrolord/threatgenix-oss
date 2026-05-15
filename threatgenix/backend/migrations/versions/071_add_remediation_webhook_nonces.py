"""Add durable remediation webhook nonces.

Revision ID: 071
Revises: 070
Create Date: 2026-05-01
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "071"
down_revision = "070"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "remediation_webhook_nonces" not in inspector.get_table_names():
        op.create_table(
            "remediation_webhook_nonces",
            sa.Column(
                "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
            ),
            sa.Column("scope", sa.String(length=120), nullable=False),
            sa.Column("nonce_hash", sa.String(length=64), nullable=False),
            sa.Column("provider", sa.String(length=40), nullable=True),
            sa.Column(
                "received_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint(
                "scope",
                "nonce_hash",
                name="uq_remediation_webhook_nonces_scope_nonce_hash",
            ),
        )
        existing_indexes: set[str] = set()
    else:
        existing_indexes = {
            index["name"]
            for index in inspector.get_indexes("remediation_webhook_nonces")
        }
    if "ix_remediation_webhook_nonces_expires_at" not in existing_indexes:
        op.create_index(
            "ix_remediation_webhook_nonces_expires_at",
            "remediation_webhook_nonces",
            ["expires_at"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "remediation_webhook_nonces" not in inspector.get_table_names():
        return
    existing_indexes = {
        index["name"] for index in inspector.get_indexes("remediation_webhook_nonces")
    }
    if "ix_remediation_webhook_nonces_expires_at" in existing_indexes:
        op.drop_index(
            "ix_remediation_webhook_nonces_expires_at",
            table_name="remediation_webhook_nonces",
        )
    op.drop_table("remediation_webhook_nonces")
