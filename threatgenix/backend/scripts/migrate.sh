#!/bin/sh
# migrate.sh — safe alembic upgrade for Fly.io release command.
# Handles the case where create_all() in seed.py created tables ahead of alembic.
set -e
cd /app

echo "==> Checking alembic state"

# Detect if tables exist but alembic is far behind (create_all ran at startup
# before migrations were fully applied). Only stamp to head when critical
# runtime columns already exist; otherwise stamp to the repair baseline so the
# repair migration still runs. Some production databases were historically
# stamped ahead after create_all(); keep this guard tied to concrete runtime
# schema, not just alembic_version.
STAMP_TARGET=$(python - <<'PYEOF'
import asyncio, os, re
import asyncpg

RUNNER_SCAN_JOB_COLUMNS = {
    "attempt_count",
    "claimed_at",
    "failure_code",
    "heartbeat_at",
    "lease_expires_at",
    "max_attempts",
    "runner_id",
}

RUNNER_TABLES = {
    "validation_artifact_bundles",
    "validation_artifact_bundle_items",
    "validation_worker_heartbeats",
}

REPORT_ATTESTATION_COLUMNS = {
    "analyst_attestation",
    "analyst_name",
    "next_review_date",
    "out_of_scope_statement",
}

TARGET_BUNDLE_TABLES = {
    "validation_target_bundles",
}

async def main():
    url = os.environ.get("DATABASE_URL", "")
    url = re.sub(r"^postgres://", "postgresql://", url)
    url = re.sub(r"[?&]sslmode=[^&]*", "", url).rstrip("?")
    ssl = "require" if os.environ.get("DATABASE_SSL", "").lower() in ("require", "true", "1") else None
    try:
        conn = await asyncpg.connect(url, ssl=ssl)
        table_count = await conn.fetchval(
            "SELECT COUNT(*) FROM information_schema.tables "
            "WHERE table_schema='public' AND table_name NOT IN ('alembic_version')"
        )
        critical_columns = await conn.fetchval(
            """
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND (
                (table_name = 'users' AND column_name = 'email_verified')
                OR (table_name = 'organizations' AND column_name IN ('subscription_tier', 'is_active'))
              )
            """
        )
        runner_columns = {
            row["column_name"]
            for row in await conn.fetch(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'scan_jobs'
                  AND column_name = ANY($1::text[])
                """,
                list(RUNNER_SCAN_JOB_COLUMNS),
            )
        }
        runner_tables = {
            row["table_name"]
            for row in await conn.fetch(
                """
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public'
                  AND table_name = ANY($1::text[])
                """,
                list(RUNNER_TABLES),
            )
        }
        report_columns = {
            row["column_name"]
            for row in await conn.fetch(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'threat_models'
                  AND column_name = ANY($1::text[])
                """,
                list(REPORT_ATTESTATION_COLUMNS),
            )
        }
        target_bundle_tables = {
            row["table_name"]
            for row in await conn.fetch(
                """
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public'
                  AND table_name = ANY($1::text[])
                """,
                list(TARGET_BUNDLE_TABLES),
            )
        }
        runner_schema_ready = (
            runner_columns == RUNNER_SCAN_JOB_COLUMNS
            and runner_tables == RUNNER_TABLES
        )
        report_schema_ready = report_columns == REPORT_ATTESTATION_COLUMNS
        target_bundle_schema_ready = target_bundle_tables == TARGET_BUNDLE_TABLES
        try:
            versions = {
                row["version_num"]
                for row in await conn.fetch("SELECT version_num FROM alembic_version")
            }
        except Exception:
            versions = set()
        await conn.close()
        # If the DB has many tables (create_all ran) but alembic trails behind the
        # latest batch of migrations, stamp to head so upgrade is a clean no-op.
        import os as _os
        versions_dir = "/app/migrations/versions"
        latest_known = set()
        if _os.path.isdir(versions_dir):
            for fname in _os.listdir(versions_dir):
                m = re.match(r'^(\d+)_', fname)
                if m:
                    latest_known.add(m.group(1))
        if table_count > 20 and not (versions & latest_known):
            if critical_columns != 3:
                print("057")
            elif not runner_schema_ready:
                print("058")
            elif not report_schema_ready:
                print("063")
            elif not target_bundle_schema_ready:
                print("065")
            else:
                print("head")
            return
        if "059" in versions and not runner_schema_ready:
            print("058")
            return
        if "064" in versions and not report_schema_ready:
            print("063")
            return
        if "066" in versions and not target_bundle_schema_ready:
            print("065")
            return
    except Exception as e:
        import sys
        print(f"check-failed: {e}", file=sys.stderr)
    print("")

asyncio.run(main())
PYEOF
)

if [ -n "$STAMP_TARGET" ]; then
    echo "==> Tables exist from create_all() but alembic is behind — stamping to $STAMP_TARGET"
    python -m alembic stamp "$STAMP_TARGET"
fi

echo "==> Running alembic upgrade head"
python -m alembic upgrade head
echo "==> Migrations complete"
