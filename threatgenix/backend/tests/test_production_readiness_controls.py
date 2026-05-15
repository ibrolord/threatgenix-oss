from __future__ import annotations

from pathlib import Path

from app.services.production_readiness_controls import (
    REQUIRED_ALERTS,
    REQUIRED_BACKUP_RECOVERY,
    REQUIRED_KILL_SWITCHES,
    REQUIRED_ROLLBACK_PATHS,
    REQUIRED_RUNBOOKS,
    REQUIRED_TRUST_CONTROLS,
    STATUS_FAIL,
    STATUS_PASS,
    validate_production_readiness_controls,
)


APP_ROOT = Path(__file__).resolve().parents[1]
DOC_PATH = APP_ROOT.parent / "docs" / "operations" / "production-readiness-controls.md"


def test_production_readiness_controls_document_covers_v1_operating_gate():
    result = validate_production_readiness_controls(DOC_PATH)

    assert result.status == STATUS_PASS, {
        check.name: check.missing for check in result.checks if check.missing
    }
    assert {check.name for check in result.checks} == {
        "alerts",
        "runbooks",
        "kill switches",
        "backup and recovery",
        "customer trust controls",
        "rollback paths",
    }


def test_production_readiness_control_catalog_matches_required_plan_scope():
    assert set(REQUIRED_ALERTS) == {
        "scanner queue stalled",
        "ai provider outage",
        "review failure spike",
        "bundle storage near quota",
        "cross-tenant access attempt",
    }
    assert set(REQUIRED_RUNBOOKS) == {
        "scanner queue stalled",
        "ai provider outage",
        "bundle storage full",
        "github app outage",
        "rollback scanner ruleset",
        "rollback prompt version",
    }
    assert set(REQUIRED_KILL_SWITCHES) == {
        "ai explanations",
        "scanner rule packs",
        "prompt versions",
        "new workers",
    }
    assert set(REQUIRED_BACKUP_RECOVERY) == {
        "backup cadence",
        "bundle storage restore",
        "evidence hash verification",
        "manual restore smoke test",
        "manual recovery path",
    }
    assert set(REQUIRED_TRUST_CONTROLS) == {
        "data retention policy",
        "upload consent event",
        "scanner execution policy",
        "no default active external scanning",
        "exportable review packet",
        "audit log",
        "model/ai limitations",
        "storage region",
        "ai inference provider/region path",
    }
    assert set(REQUIRED_ROLLBACK_PATHS) == {
        "scanner ruleset rollback",
        "prompt version rollback",
        "worker image rollback",
    }


def test_production_readiness_controls_fail_when_required_runbook_is_missing(tmp_path):
    incomplete = tmp_path / "production-readiness-controls.md"
    incomplete.write_text(
        """
        scanner queue stalled
        ai provider outage
        review failure spike
        bundle storage near quota
        cross-tenant access attempt
        """,
        encoding="utf-8",
    )

    result = validate_production_readiness_controls(incomplete)

    assert result.status == STATUS_FAIL
    checks = {check.name: check for check in result.checks}
    assert "github app outage" in checks["runbooks"].missing
    assert "prompt version rollback" in checks["rollback paths"].missing
