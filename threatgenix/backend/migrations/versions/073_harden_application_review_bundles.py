"""Harden application review bundle integrity metadata.

Revision ID: 073
Revises: 072
Create Date: 2026-05-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "073"
down_revision = "072"
branch_labels = None
depends_on = None


def _has_column(inspector, table_name: str, column_name: str) -> bool:
    return column_name in {column["name"] for column in inspector.get_columns(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "application_review_bundles" not in inspector.get_table_names():
        return

    additions = [
        (
            "redaction_report",
            sa.Column(
                "redaction_report",
                postgresql.JSONB(astext_type=sa.Text()),
                server_default=sa.text("'{}'::jsonb"),
                nullable=False,
            ),
        ),
        (
            "integrity",
            sa.Column(
                "integrity",
                postgresql.JSONB(astext_type=sa.Text()),
                server_default=sa.text("'{}'::jsonb"),
                nullable=False,
            ),
        ),
        (
            "storage_backend",
            sa.Column("storage_backend", sa.String(length=40), server_default="database_manifest", nullable=False),
        ),
        (
            "encryption_status",
            sa.Column("encryption_status", sa.String(length=40), server_default="metadata_only", nullable=False),
        ),
        ("retention_expires_at", sa.Column("retention_expires_at", sa.DateTime(timezone=True), nullable=True)),
        ("legal_hold", sa.Column("legal_hold", sa.Boolean(), server_default=sa.false(), nullable=False)),
    ]
    for column_name, column in additions:
        if not _has_column(inspector, "application_review_bundles", column_name):
            op.add_column("application_review_bundles", column)

    op.execute(
        "ALTER TABLE application_review_bundles "
        "DROP CONSTRAINT IF EXISTS ck_application_review_bundles_kind"
    )
    op.create_check_constraint(
        "ck_application_review_bundles_kind",
        "application_review_bundles",
        "bundle_kind IN ('diff','snapshot','metadata','existing_evidence')",
    )
    op.execute(
        "ALTER TABLE application_review_bundles "
        "DROP CONSTRAINT IF EXISTS ck_application_review_bundles_status"
    )
    op.create_check_constraint(
        "ck_application_review_bundles_status",
        "application_review_bundles",
        "status IN ('ready','superseded','deleted')",
    )

    existing_indexes = {
        index["name"]
        for index in inspector.get_indexes("application_review_bundles")
    }
    if "ix_application_review_bundles_one_ready" not in existing_indexes:
        op.create_index(
            "ix_application_review_bundles_one_ready",
            "application_review_bundles",
            ["tenant_key", "review_id"],
            unique=True,
            postgresql_where=sa.text("status = 'ready'"),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "application_review_bundles" not in inspector.get_table_names():
        return

    existing_indexes = {
        index["name"]
        for index in inspector.get_indexes("application_review_bundles")
    }
    if "ix_application_review_bundles_one_ready" in existing_indexes:
        op.drop_index("ix_application_review_bundles_one_ready", table_name="application_review_bundles")

    op.execute(
        "ALTER TABLE application_review_bundles "
        "DROP CONSTRAINT IF EXISTS ck_application_review_bundles_status"
    )
    op.execute(
        "UPDATE application_review_bundles SET status = 'deleted' "
        "WHERE status = 'superseded'"
    )
    op.create_check_constraint(
        "ck_application_review_bundles_status",
        "application_review_bundles",
        "status IN ('ready','deleted')",
    )
    op.execute(
        "ALTER TABLE application_review_bundles "
        "DROP CONSTRAINT IF EXISTS ck_application_review_bundles_kind"
    )
    op.execute(
        "UPDATE application_review_bundles SET bundle_kind = 'metadata' "
        "WHERE bundle_kind = 'existing_evidence'"
    )
    op.create_check_constraint(
        "ck_application_review_bundles_kind",
        "application_review_bundles",
        "bundle_kind IN ('diff','snapshot','metadata')",
    )

    for column_name in (
        "legal_hold",
        "retention_expires_at",
        "encryption_status",
        "storage_backend",
        "integrity",
        "redaction_report",
    ):
        if _has_column(inspector, "application_review_bundles", column_name):
            op.drop_column("application_review_bundles", column_name)
