"""Repair SaaS/auth columns for databases stamped ahead of schema.

Revision ID: 057
Revises: 056
Create Date: 2026-04-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "057"
down_revision = "056"
branch_labels = None
depends_on = None


def _inspector():
    return sa.inspect(op.get_bind())


def _has_table(table_name: str) -> bool:
    return table_name in _inspector().get_table_names()


def _has_column(table_name: str, column_name: str) -> bool:
    return any(
        column["name"] == column_name
        for column in _inspector().get_columns(table_name)
    )


def _has_index(table_name: str, index_name: str) -> bool:
    if not _has_table(table_name):
        return False
    return any(
        index["name"] == index_name
        for index in _inspector().get_indexes(table_name)
    )


def upgrade() -> None:
    if not _has_column("organizations", "subscription_tier"):
        op.add_column(
            "organizations",
            sa.Column(
                "subscription_tier",
                sa.String(50),
                nullable=False,
                server_default="free",
                comment="Billing tier: free, pro, enterprise.",
            ),
        )
    if not _has_column("organizations", "is_active"):
        op.add_column(
            "organizations",
            sa.Column(
                "is_active",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("true"),
                comment="Whether this organization is active (billing/admin toggle).",
            ),
        )
    if not _has_column("users", "email_verified"):
        op.add_column(
            "users",
            sa.Column(
                "email_verified",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
                comment="Set to True after the user verifies their email address.",
            ),
        )

    if not _has_table("email_verifications"):
        op.create_table(
            "email_verifications",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
            sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column(
                "code_hash",
                sa.String(64),
                nullable=False,
                comment="HMAC-SHA256 hex digest of the verification code.",
            ),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        )
    if not _has_index("email_verifications", "ix_email_verifications_user_id"):
        op.create_index(
            "ix_email_verifications_user_id",
            "email_verifications",
            ["user_id"],
        )

    if not _has_table("password_reset_tokens"):
        op.create_table(
            "password_reset_tokens",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
            sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column(
                "token_hash",
                sa.String(64),
                nullable=False,
                comment="HMAC-SHA256 hex digest of the reset token.",
            ),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        )
    if not _has_index("password_reset_tokens", "ix_password_reset_tokens_user_id"):
        op.create_index(
            "ix_password_reset_tokens_user_id",
            "password_reset_tokens",
            ["user_id"],
        )


def downgrade() -> None:
    if _has_table("password_reset_tokens"):
        op.drop_table("password_reset_tokens")
    if _has_table("email_verifications"):
        op.drop_table("email_verifications")
    if _has_column("users", "email_verified"):
        op.drop_column("users", "email_verified")
    if _has_column("organizations", "is_active"):
        op.drop_column("organizations", "is_active")
    if _has_column("organizations", "subscription_tier"):
        op.drop_column("organizations", "subscription_tier")
