"""Repair workbench and report-template schema drift after duplicate revisions.

Revision ID: 033
Revises: 032
Create Date: 2026-04-22
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "033"
down_revision = "032"
branch_labels = None
depends_on = None


def _has_column(table_name: str, column_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def _has_check_constraint(table_name: str, constraint_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(
        constraint["name"] == constraint_name
        for constraint in inspector.get_check_constraints(table_name)
    )


def upgrade() -> None:
    if not _has_column("threat_models", "report_templates"):
        op.add_column(
            "threat_models",
            sa.Column(
                "report_templates",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=True,
                comment="Custom structured report templates defined for this threat model.",
            ),
        )

    if not _has_column("threat_models", "review_state"):
        op.add_column(
            "threat_models",
            sa.Column(
                "review_state",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=True,
                comment="Persisted security review workbench state for findings and queue history.",
            ),
        )

    if not _has_column("users", "report_template_library"):
        op.add_column(
            "users",
            sa.Column(
                "report_template_library",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=True,
                comment="User-scoped reusable report templates available across threat models.",
            ),
        )

    if not _has_column("threats", "qualification_score"):
        op.add_column(
            "threats",
            sa.Column("qualification_score", sa.Integer(), nullable=True),
        )

    if not _has_column("threats", "qualification_note"):
        op.add_column(
            "threats",
            sa.Column("qualification_note", sa.Text(), nullable=True),
        )

    if not _has_check_constraint("threats", "ck_threats_qualification_score_range"):
        op.create_check_constraint(
            "ck_threats_qualification_score_range",
            "threats",
            "qualification_score IS NULL OR (qualification_score >= 0 AND qualification_score <= 100)",
        )


def downgrade() -> None:
    if _has_check_constraint("threats", "ck_threats_qualification_score_range"):
        op.drop_constraint("ck_threats_qualification_score_range", "threats")
    if _has_column("threats", "qualification_note"):
        op.drop_column("threats", "qualification_note")
    if _has_column("threats", "qualification_score"):
        op.drop_column("threats", "qualification_score")
