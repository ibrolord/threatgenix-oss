"""Backfill null owner_id rows and add NOT NULL constraint.

Revision ID: 047
Revises: 046
Create Date: 2026-04-27
"""

from alembic import op
import sqlalchemy as sa

revision = "047"
down_revision = "046"
branch_labels = None
depends_on = None

# Sentinel UUID used to backfill rows with missing owner_id.
# This is a well-known value so it can be identified later if needed.
SENTINEL_OWNER_UUID = "00000000-0000-0000-0000-000000000000"
SENTINEL_ORG_UUID = "00000000-0000-0000-0000-000000000001"
SENTINEL_EMAIL = "legacy-owner@threatgenix.local"


def _has_table(table_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return table_name in inspector.get_table_names()


def _has_column(table_name: str, column_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def _ensure_sentinel_owner() -> None:
    """Create a disabled sentinel user so owner_id backfill keeps FK integrity."""
    bind = op.get_bind()
    if not _has_table("users"):
        return

    if _has_table("organizations") and _has_column("users", "organization_id"):
        bind.execute(
            sa.text(
                """
                INSERT INTO organizations (id, name, subscription_tier, is_active)
                VALUES (:id, 'Legacy ThreatGenix Imports', 'free', false)
                ON CONFLICT (id) DO NOTHING
                """
            ),
            {"id": SENTINEL_ORG_UUID},
        )

    columns = [
        "id",
        "email",
        "hashed_password",
        "full_name",
        "role",
        "is_active",
    ]
    values = {
        "id": SENTINEL_OWNER_UUID,
        "email": SENTINEL_EMAIL,
        "hashed_password": "disabled-legacy-owner",
        "full_name": "Legacy ThreatGenix Owner",
        "role": "admin",
        "is_active": False,
    }
    if _has_column("users", "email_verified"):
        columns.append("email_verified")
        values["email_verified"] = True
    if _has_column("users", "organization_id"):
        columns.append("organization_id")
        values["organization_id"] = (
            SENTINEL_ORG_UUID if _has_table("organizations") else None
        )

    column_sql = ", ".join(columns)
    value_sql = ", ".join(f":{column}" for column in columns)
    bind.execute(
        sa.text(
            f"""
            INSERT INTO users ({column_sql})
            VALUES ({value_sql})
            ON CONFLICT (id) DO NOTHING
            """
        ),
        values,
    )


def upgrade() -> None:
    _ensure_sentinel_owner()

    # Step 1: Backfill any NULL owner_id rows with the disabled sentinel user.
    op.execute(
        sa.text(
            f"UPDATE threat_models SET owner_id = '{SENTINEL_OWNER_UUID}' WHERE owner_id IS NULL"
        )
    )

    # Step 2: Add NOT NULL constraint.
    # Use batch_alter_table for SQLite compatibility (tests).
    with op.batch_alter_table("threat_models") as batch_op:
        batch_op.alter_column("owner_id", existing_type=sa.Uuid(), nullable=False)


def downgrade() -> None:
    with op.batch_alter_table("threat_models") as batch_op:
        batch_op.alter_column("owner_id", existing_type=sa.Uuid(), nullable=True)
