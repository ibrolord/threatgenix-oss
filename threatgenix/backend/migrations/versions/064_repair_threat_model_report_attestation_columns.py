"""Repair threat-model report attestation schema drift.

Revision ID: 064
Revises: 063
Create Date: 2026-04-30
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "064"
down_revision = "063"
branch_labels = None
depends_on = None


def _has_table(table_name: str) -> bool:
    return table_name in sa.inspect(op.get_bind()).get_table_names()


def _has_column(table_name: str, column_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def _add_column_if_missing(table_name: str, column: sa.Column) -> None:
    if _has_table(table_name) and not _has_column(table_name, column.name):
        op.add_column(table_name, column)


def _drop_column_if_present(table_name: str, column_name: str) -> None:
    if _has_table(table_name) and _has_column(table_name, column_name):
        op.drop_column(table_name, column_name)


def upgrade() -> None:
    _add_column_if_missing(
        "threat_models",
        sa.Column(
            "analyst_name",
            sa.String(255),
            nullable=True,
            comment="Name of the analyst who produced this threat model.",
        ),
    )
    _add_column_if_missing(
        "threat_models",
        sa.Column(
            "analyst_attestation",
            sa.Text(),
            nullable=True,
            comment="Analyst sign-off statement affirming accuracy and completeness of the threat model.",
        ),
    )
    _add_column_if_missing(
        "threat_models",
        sa.Column(
            "next_review_date",
            sa.Date(),
            nullable=True,
            comment="Next scheduled review date for the threat model.",
        ),
    )
    _add_column_if_missing(
        "threat_models",
        sa.Column(
            "out_of_scope_statement",
            sa.Text(),
            nullable=True,
            comment="Explicit scope exclusions documented for report consumers.",
        ),
    )


def downgrade() -> None:
    _drop_column_if_present("threat_models", "out_of_scope_statement")
    _drop_column_if_present("threat_models", "next_review_date")
    _drop_column_if_present("threat_models", "analyst_attestation")
    _drop_column_if_present("threat_models", "analyst_name")
