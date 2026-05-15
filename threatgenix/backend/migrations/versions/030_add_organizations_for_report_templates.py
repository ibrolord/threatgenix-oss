"""Add organizations and move shared report templates to organization scope.

Revision ID: 030
Revises: 029
Create Date: 2026-04-18
"""

from __future__ import annotations

import re
import uuid

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "030"
down_revision = "029"
branch_labels = None
depends_on = None


def _has_table(table_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return table_name in inspector.get_table_names()


def _has_column(table_name: str, column_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def _has_index(table_name: str, index_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(index["name"] == index_name for index in inspector.get_indexes(table_name))


def _has_foreign_key(table_name: str, constrained_column: str, referred_table: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(
        fk.get("referred_table") == referred_table
        and constrained_column in fk.get("constrained_columns", [])
        for fk in inspector.get_foreign_keys(table_name)
    )


def _build_organization_name(full_name: str | None, email: str | None) -> str:
    normalized_full_name = re.sub(r"\s+", " ", (full_name or "")).strip()
    if normalized_full_name:
        if normalized_full_name.endswith("s"):
            return f"{normalized_full_name}' Organization"
        return f"{normalized_full_name}'s Organization"

    local_part = (email or "").split("@", 1)[0].strip()
    if not local_part:
        return "ThreatGenix Organization"
    words = [part for part in re.split(r"[^A-Za-z0-9]+", local_part) if part]
    title = " ".join(word.capitalize() for word in words) or "ThreatGenix"
    return f"{title} Organization"


def upgrade() -> None:
    bind = op.get_bind()

    if not _has_table("organizations"):
        op.create_table(
            "organizations",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column(
                "report_template_library",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=True,
                comment="Organization-scoped reusable report templates available across threat models.",
            ),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
        )

    if not _has_column("users", "organization_id"):
        op.add_column(
            "users",
            sa.Column(
                "organization_id",
                postgresql.UUID(as_uuid=True),
                nullable=True,
            ),
        )

    if not _has_index("users", "ix_users_organization_id"):
        op.create_index("ix_users_organization_id", "users", ["organization_id"])

    if not _has_foreign_key("users", "organization_id", "organizations"):
        op.create_foreign_key(
            "fk_users_organization_id",
            "users",
            "organizations",
            ["organization_id"],
            ["id"],
        )

    users = sa.table(
        "users",
        sa.column("id", postgresql.UUID(as_uuid=True)),
        sa.column("email", sa.String()),
        sa.column("full_name", sa.String()),
        sa.column("organization_id", postgresql.UUID(as_uuid=True)),
        sa.column("report_template_library", postgresql.JSONB(astext_type=sa.Text())),
    )
    organizations = sa.table(
        "organizations",
        sa.column("id", postgresql.UUID(as_uuid=True)),
        sa.column("name", sa.String()),
        sa.column("report_template_library", postgresql.JSONB(astext_type=sa.Text())),
    )

    existing_users = bind.execute(
        sa.select(
            users.c.id,
            users.c.email,
            users.c.full_name,
            users.c.organization_id,
            users.c.report_template_library,
        )
    ).mappings()

    for row in existing_users:
        if row["organization_id"] is not None:
            continue
        organization_id = uuid.uuid4()
        bind.execute(
            organizations.insert().values(
                id=organization_id,
                name=_build_organization_name(row["full_name"], row["email"]),
                report_template_library=row["report_template_library"],
            )
        )
        bind.execute(
            users.update()
            .where(users.c.id == row["id"])
            .values(organization_id=organization_id, report_template_library=None)
        )


def downgrade() -> None:
    pass
