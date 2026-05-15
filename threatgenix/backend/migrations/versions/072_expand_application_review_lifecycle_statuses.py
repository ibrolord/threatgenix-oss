"""Expand application review lifecycle statuses.

Revision ID: 072
Revises: 071
Create Date: 2026-05-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "072"
down_revision = "071"
branch_labels = None
depends_on = None

REVIEW_STATUSES = (
    "created",
    "intake_required",
    "bundle_required",
    "bundle_received",
    "scanning",
    "extracting_context",
    "indexing",
    "building_graph",
    "deciding",
    "explaining",
    "completed",
    "blocked_by_policy",
    "blocked_by_permission",
    "failed_retryable",
    "failed_terminal",
    "cancelled",
)


def _status_sql(statuses: tuple[str, ...]) -> str:
    return ",".join(f"'{status}'" for status in statuses)


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "application_security_reviews" not in inspector.get_table_names():
        return

    op.execute(
        "ALTER TABLE application_security_reviews "
        "DROP CONSTRAINT IF EXISTS ck_application_security_reviews_status"
    )
    op.execute(
        "ALTER TABLE application_security_reviews "
        "ALTER COLUMN status TYPE VARCHAR(32)"
    )
    op.execute(
        "UPDATE application_security_reviews "
        "SET status = CASE status "
        "WHEN 'pending' THEN 'created' "
        "WHEN 'running' THEN 'scanning' "
        "WHEN 'failed' THEN 'failed_retryable' "
        "ELSE status END"
    )
    op.execute(
        "ALTER TABLE application_security_reviews "
        "ALTER COLUMN status SET DEFAULT 'created'"
    )
    op.create_check_constraint(
        "ck_application_security_reviews_status",
        "application_security_reviews",
        f"status IN ({_status_sql(REVIEW_STATUSES)})",
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "application_security_reviews" not in inspector.get_table_names():
        return

    op.execute(
        "ALTER TABLE application_security_reviews "
        "DROP CONSTRAINT IF EXISTS ck_application_security_reviews_status"
    )
    op.execute(
        "UPDATE application_security_reviews "
        "SET status = CASE "
        "WHEN status IN ('created','intake_required','bundle_required','bundle_received') "
        "THEN 'pending' "
        "WHEN status IN ('scanning','extracting_context','indexing','building_graph','deciding','explaining') "
        "THEN 'running' "
        "WHEN status IN ('failed_retryable','failed_terminal') THEN 'failed' "
        "ELSE status END"
    )
    op.execute(
        "ALTER TABLE application_security_reviews "
        "ALTER COLUMN status SET DEFAULT 'pending'"
    )
    op.execute(
        "ALTER TABLE application_security_reviews "
        "ALTER COLUMN status TYPE VARCHAR(20)"
    )
    op.create_check_constraint(
        "ck_application_security_reviews_status",
        "application_security_reviews",
        "status IN ('pending','running','completed','failed','cancelled')",
    )
