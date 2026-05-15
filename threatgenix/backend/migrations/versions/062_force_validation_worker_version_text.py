"""Force validation worker heartbeat version to text.

Revision ID: 062
Revises: 061
Create Date: 2026-04-29
"""

from __future__ import annotations

from alembic import op

revision = "062"
down_revision = "061"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'validation_worker_heartbeats'
                  AND column_name = 'version'
            ) THEN
                ALTER TABLE public.validation_worker_heartbeats
                    ALTER COLUMN version TYPE TEXT USING version::text;
            END IF;
        END $$;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'validation_worker_heartbeats'
                  AND column_name = 'version'
            ) THEN
                ALTER TABLE public.validation_worker_heartbeats
                    ALTER COLUMN version TYPE VARCHAR(200) USING left(version, 200);
            END IF;
        END $$;
        """
    )
