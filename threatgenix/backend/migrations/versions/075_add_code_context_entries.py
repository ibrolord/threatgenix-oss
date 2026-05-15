"""Add code context index entry types.

Revision ID: 075
Revises: 074
Create Date: 2026-05-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "075"
down_revision = "074"
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
    "code_context",
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
    "code_context",
)

PREVIOUS_SOURCE_TYPES = SOURCE_TYPES[:-1]
PREVIOUS_ITEM_TYPES = ITEM_TYPES[:-1]


def _quoted(values: tuple[str, ...]) -> str:
    return ",".join(f"'{value}'" for value in values)


def upgrade() -> None:
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
        f"source_type IN ({_quoted(SOURCE_TYPES)})",
    )
    op.create_check_constraint(
        "ck_application_review_context_entries_item_type",
        "application_review_context_entries",
        f"item_type IN ({_quoted(ITEM_TYPES)})",
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "application_review_context_entries" not in inspector.get_table_names():
        return
    op.execute(
        "DELETE FROM application_review_context_entries "
        "WHERE source_type = 'code_context' OR item_type = 'code_context'"
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
        f"source_type IN ({_quoted(PREVIOUS_SOURCE_TYPES)})",
    )
    op.create_check_constraint(
        "ck_application_review_context_entries_item_type",
        "application_review_context_entries",
        f"item_type IN ({_quoted(PREVIOUS_ITEM_TYPES)})",
    )
