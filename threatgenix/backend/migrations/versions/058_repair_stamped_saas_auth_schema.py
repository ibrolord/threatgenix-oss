"""Repair stamped production databases missing SaaS/auth schema.

Revision ID: 058
Revises: 057
Create Date: 2026-04-29
"""

from __future__ import annotations

from alembic import op

revision = "058"
down_revision = "057"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE organizations
        ADD COLUMN IF NOT EXISTS subscription_tier varchar(50) NOT NULL DEFAULT 'free';
        """
    )
    op.execute(
        """
        ALTER TABLE organizations
        ADD COLUMN IF NOT EXISTS is_active boolean NOT NULL DEFAULT true;
        """
    )
    op.execute(
        """
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS email_verified boolean NOT NULL DEFAULT false;
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS email_verifications (
            id uuid PRIMARY KEY,
            user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            code_hash varchar(64) NOT NULL,
            expires_at timestamptz NOT NULL,
            used boolean NOT NULL DEFAULT false,
            created_at timestamptz NOT NULL DEFAULT now()
        );
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_email_verifications_user_id
        ON email_verifications (user_id);
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id uuid PRIMARY KEY,
            user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash varchar(64) NOT NULL,
            expires_at timestamptz NOT NULL,
            used boolean NOT NULL DEFAULT false,
            created_at timestamptz NOT NULL DEFAULT now()
        );
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_password_reset_tokens_user_id
        ON password_reset_tokens (user_id);
        """
    )
    op.execute(
        """
        COMMENT ON COLUMN organizations.subscription_tier
        IS 'Billing tier: free, pro, enterprise.';
        """
    )
    op.execute(
        """
        COMMENT ON COLUMN organizations.is_active
        IS 'Whether this organization is active (billing/admin toggle).';
        """
    )
    op.execute(
        """
        COMMENT ON COLUMN users.email_verified
        IS 'Set to True after the user verifies their email address.';
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS password_reset_tokens;")
    op.execute("DROP TABLE IF EXISTS email_verifications;")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS email_verified;")
    op.execute("ALTER TABLE organizations DROP COLUMN IF EXISTS is_active;")
    op.execute("ALTER TABLE organizations DROP COLUMN IF EXISTS subscription_tier;")
