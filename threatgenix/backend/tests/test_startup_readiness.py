from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI

from app import main as app_main


def _set_hardened_production_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_main.settings, "app_env", "production")
    monkeypatch.setattr(app_main.settings, "secret_key", "x" * 48)
    monkeypatch.setattr(
        app_main.settings,
        "database_url",
        "postgresql+asyncpg://threatgenix:password@postgres.example.test:5432/threatgenix",
    )
    monkeypatch.setattr(app_main.settings, "allowed_origins", "https://app.example.test")
    monkeypatch.setattr(app_main.settings, "trusted_hosts", "api.example.test")
    monkeypatch.setattr(app_main.settings, "auth_expose_dev_tokens", False)


def test_required_schema_columns_cover_evidence_graph_runtime_tables():
    for table_name in [
        "evidence_items",
        "evidence_observations",
        "evidence_relationships",
        "evidence_finding_links",
    ]:
        assert table_name in app_main.REQUIRED_SCHEMA_COLUMNS
        assert "threat_model_id" in app_main.REQUIRED_SCHEMA_COLUMNS[table_name]


def test_required_schema_columns_cover_managed_runner_runtime_columns():
    assert {
        "attempt_count",
        "claimed_at",
        "failure_code",
        "heartbeat_at",
        "lease_expires_at",
        "max_attempts",
        "runner_id",
    }.issubset(app_main.REQUIRED_SCHEMA_COLUMNS["scan_jobs"])
    assert {
        "current_scan_job_id",
        "last_seen_at",
        "runner_id",
        "runtime_mode",
        "sandbox_mode",
        "status",
        "version",
    }.issubset(app_main.REQUIRED_SCHEMA_COLUMNS["validation_worker_heartbeats"])


def test_required_schema_columns_cover_report_attestation_runtime_columns():
    assert {
        "analyst_attestation",
        "analyst_name",
        "next_review_date",
        "out_of_scope_statement",
        "report_logo_base64",
        "report_template",
        "report_watermark_text",
    }.issubset(app_main.REQUIRED_SCHEMA_COLUMNS["threat_models"])


def test_required_schema_columns_cover_remediation_webhook_nonce_runtime_table():
    assert {
        "expires_at",
        "nonce_hash",
        "received_at",
        "scope",
    }.issubset(app_main.REQUIRED_SCHEMA_COLUMNS["remediation_webhook_nonces"])


def test_required_schema_columns_cover_risk_acceptance_lifecycle_table():
    assert {
        "tenant_key",
        "review_id",
        "scope_type",
        "scope_value",
        "approver_id",
        "expires_at",
        "status",
        "audit_events",
    }.issubset(app_main.REQUIRED_SCHEMA_COLUMNS["application_risk_acceptances"])


def test_required_alembic_revision_matches_latest_migration():
    versions_dir = Path(__file__).resolve().parent.parent / "migrations" / "versions"
    latest_revision = max(
        path.name.split("_", 1)[0] for path in versions_dir.glob("[0-9][0-9][0-9]_*.py")
    )

    assert app_main.REQUIRED_ALEMBIC_REVISION == latest_revision


def test_release_migration_repairs_runner_schema_when_stamped_head():
    migrate_script = (
        Path(__file__).resolve().parent.parent / "scripts" / "migrate.sh"
    ).read_text()

    assert "RUNNER_SCAN_JOB_COLUMNS" in migrate_script
    assert "validation_worker_heartbeats" in migrate_script
    assert 'if "059" in versions and not runner_schema_ready:' in migrate_script
    assert 'print("058")' in migrate_script
    assert "REPORT_ATTESTATION_COLUMNS" in migrate_script
    assert 'if "064" in versions and not report_schema_ready:' in migrate_script
    assert 'print("063")' in migrate_script


@pytest.mark.asyncio
async def test_production_startup_rejects_stale_alembic_revision(monkeypatch):
    _set_hardened_production_settings(monkeypatch)
    monkeypatch.setattr(
        app_main,
        "get_current_alembic_revision",
        AsyncMock(return_value="051"),
    )

    with pytest.raises(
        RuntimeError, match=f"expected {app_main.REQUIRED_ALEMBIC_REVISION}"
    ):
        async with app_main.lifespan(FastAPI()):
            pass


@pytest.mark.asyncio
async def test_startup_rejects_missing_required_runtime_schema(monkeypatch):
    import app.seed as seed_module
    import app.seed_demo as seed_demo_module
    import app.services.doc_cleanup as doc_cleanup_module

    monkeypatch.setattr(app_main.settings, "app_env", "development")
    monkeypatch.setattr(seed_module, "seed", AsyncMock())
    monkeypatch.setattr(seed_demo_module, "seed_demo", AsyncMock())
    monkeypatch.setattr(doc_cleanup_module, "purge_expired_documents", AsyncMock())
    monkeypatch.setattr(doc_cleanup_module, "cleanup_loop", AsyncMock())
    monkeypatch.setattr(
        app_main,
        "get_missing_required_schema",
        AsyncMock(return_value=["threat_models.review_state"]),
    )

    test_app = FastAPI()
    with pytest.raises(RuntimeError, match="threat_models.review_state"):
        async with app_main.lifespan(test_app):
            pass

    assert test_app.state.schema_ready is False
    assert (
        test_app.state.schema_error
        == "missing required database columns: threat_models.review_state. "
        "Run `alembic upgrade head`."
    )


def test_runtime_config_accepts_hardened_production_settings(monkeypatch):
    _set_hardened_production_settings(monkeypatch)

    assert app_main.validate_runtime_configuration() == []


@pytest.mark.parametrize(
    ("setting_name", "unsafe_value", "expected_error"),
    [
        (
            "secret_key",
            app_main.DEFAULT_DEV_SECRET_KEY,
            "SECRET_KEY must be a non-default value",
        ),
        ("secret_key", "short", "SECRET_KEY must be a non-default value"),
        (
            "database_url",
            "postgresql+asyncpg://threatgenix:password@db:5432/threatgenix",
            "DATABASE_URL must point to a production database",
        ),
        (
            "database_url",
            "postgresql+asyncpg://threatgenix:password@localhost:5432/threatgenix",
            "DATABASE_URL must point to a production database",
        ),
        (
            "allowed_origins",
            "",
            "ALLOWED_ORIGINS must include the public HTTPS frontend origin",
        ),
        ("allowed_origins", "*", "ALLOWED_ORIGINS cannot use wildcards"),
        (
            "allowed_origins",
            "http://app.example.test",
            "ALLOWED_ORIGINS entry must use https",
        ),
        (
            "allowed_origins",
            "https://localhost:5173",
            "ALLOWED_ORIGINS entry cannot be loopback",
        ),
        (
            "trusted_hosts",
            "",
            "TRUSTED_HOSTS must include the public API host in production",
        ),
        ("trusted_hosts", "*", "TRUSTED_HOSTS cannot use wildcards"),
        (
            "trusted_hosts",
            "localhost",
            "TRUSTED_HOSTS entry cannot be loopback",
        ),
        (
            "auth_expose_dev_tokens",
            True,
            "AUTH_EXPOSE_DEV_TOKENS must be false in production",
        ),
    ],
)
def test_runtime_config_rejects_each_unsafe_production_setting(
    monkeypatch: pytest.MonkeyPatch,
    setting_name: str,
    unsafe_value: object,
    expected_error: str,
):
    _set_hardened_production_settings(monkeypatch)
    monkeypatch.setattr(app_main.settings, setting_name, unsafe_value)

    errors = app_main.validate_runtime_configuration()

    assert any(expected_error in error for error in errors)


def test_runtime_config_rejects_insecure_production_settings(monkeypatch):
    monkeypatch.setattr(app_main.settings, "app_env", "production")
    monkeypatch.setattr(app_main.settings, "secret_key", "short")
    monkeypatch.setattr(
        app_main.settings,
        "database_url",
        "postgresql+asyncpg://threatgenix:password@db:5432/threatgenix",
    )
    monkeypatch.setattr(
        app_main.settings,
        "allowed_origins",
        "*,http://localhost:5173",
    )
    monkeypatch.setattr(app_main.settings, "trusted_hosts", "*,localhost")
    monkeypatch.setattr(app_main.settings, "auth_expose_dev_tokens", True)

    errors = app_main.validate_runtime_configuration()

    assert any("SECRET_KEY" in error for error in errors)
    assert any("DATABASE_URL" in error for error in errors)
    assert any("ALLOWED_ORIGINS cannot use wildcards" in error for error in errors)
    assert any("ALLOWED_ORIGINS entry must use https" in error for error in errors)
    assert any("ALLOWED_ORIGINS entry cannot be loopback" in error for error in errors)
    assert any("TRUSTED_HOSTS cannot use wildcards" in error for error in errors)
    assert any("TRUSTED_HOSTS entry cannot be loopback" in error for error in errors)
    assert any("AUTH_EXPOSE_DEV_TOKENS" in error for error in errors)


def test_runtime_config_rejects_missing_production_trusted_hosts(monkeypatch):
    _set_hardened_production_settings(monkeypatch)
    monkeypatch.setattr(app_main.settings, "trusted_hosts", "")

    assert any(
        "TRUSTED_HOSTS must include" in error
        for error in app_main.validate_runtime_configuration()
    )
