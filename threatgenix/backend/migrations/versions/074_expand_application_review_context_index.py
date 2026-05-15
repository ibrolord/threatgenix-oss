"""Expand application review context index.

Revision ID: 074
Revises: 073
Create Date: 2026-05-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "074"
down_revision = "073"
branch_labels = None
depends_on = None

SOURCE_TYPES = (
    "review",
    "bundle",
    "scan_finding",
    "policy",
    "manual",
    "document",
    "code_summary",
    "evidence_item",
    "evidence_entity",
    "evidence_relationship",
    "evidence_finding",
    "threat",
    "decision",
    "organization",
)

ITEM_TYPES = (
    "app_profile",
    "org_profile",
    "review_scope",
    "bundle_file",
    "scanner_finding",
    "policy",
    "control",
    "accepted_risk",
    "note",
    "doc",
    "code_summary",
    "evidence_item",
    "evidence_entity",
    "evidence_relationship",
    "evidence_finding",
    "prior_review_decision",
)


def _quoted(values: tuple[str, ...]) -> str:
    return ",".join(f"'{value}'" for value in values)


def _column_names(inspector: sa.Inspector) -> set[str]:
    return {
        column["name"]
        for column in inspector.get_columns("application_review_context_entries")
    }


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "application_review_context_entries" not in inspector.get_table_names():
        return

    columns = _column_names(inspector)
    if "facets" not in columns:
        op.add_column(
            "application_review_context_entries",
            sa.Column(
                "facets",
                postgresql.JSONB(astext_type=sa.Text()),
                server_default=sa.text("'{}'::jsonb"),
                nullable=False,
            ),
        )
    if "retrieval_text" not in columns:
        op.add_column(
            "application_review_context_entries",
            sa.Column("retrieval_text", sa.Text(), server_default="", nullable=False),
        )
    if "stale_reason" not in columns:
        op.add_column(
            "application_review_context_entries",
            sa.Column("stale_reason", sa.Text(), nullable=True),
        )

    op.execute(
        "ALTER TABLE application_review_context_entries "
        "DROP CONSTRAINT IF EXISTS ck_application_review_context_entries_source_type"
    )
    op.execute(
        "ALTER TABLE application_review_context_entries "
        "DROP CONSTRAINT IF EXISTS ck_application_review_context_entries_item_type"
    )
    op.create_check_constraint(
        "ck_application_review_context_entries_source_type",
        "application_review_context_entries",
        f"source_type IN ({_quoted(SOURCE_TYPES)})",
    )
    op.create_check_constraint(
        "ck_application_review_context_entries_item_type",
        "application_review_context_entries",
        f"item_type IN ({_quoted(ITEM_TYPES)})",
    )
    existing_indexes = {
        index["name"]
        for index in inspector.get_indexes("application_review_context_entries")
    }
    if "ix_application_review_context_item_type" not in existing_indexes:
        op.create_index(
            "ix_application_review_context_item_type",
            "application_review_context_entries",
            ["tenant_key", "review_id", "item_type", "status"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "application_review_context_entries" not in inspector.get_table_names():
        return

    op.execute(
        "ALTER TABLE application_review_context_entries "
        "DROP CONSTRAINT IF EXISTS ck_application_review_context_entries_source_type"
    )
    op.execute(
        "ALTER TABLE application_review_context_entries "
        "DROP CONSTRAINT IF EXISTS ck_application_review_context_entries_item_type"
    )
    op.create_check_constraint(
        "ck_application_review_context_entries_source_type",
        "application_review_context_entries",
        "source_type IN ('review','bundle','scan_finding','policy','manual')",
    )
    op.create_check_constraint(
        "ck_application_review_context_entries_item_type",
        "application_review_context_entries",
        "item_type IN ('app_profile','org_profile','review_scope','bundle_file',"
        "'scanner_finding','policy','accepted_risk','note')",
    )
    existing_indexes = {
        index["name"]
        for index in inspector.get_indexes("application_review_context_entries")
    }
    if "ix_application_review_context_item_type" in existing_indexes:
        op.drop_index(
            "ix_application_review_context_item_type",
            table_name="application_review_context_entries",
        )
    columns = _column_names(inspector)
    for column_name in ("stale_reason", "retrieval_text", "facets"):
        if column_name in columns:
            op.drop_column("application_review_context_entries", column_name)
