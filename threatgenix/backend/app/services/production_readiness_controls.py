"""Production readiness control catalog for invoke-anywhere releases."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


STATUS_PASS = "pass"
STATUS_FAIL = "fail"

REQUIRED_ALERTS = (
    "scanner queue stalled",
    "ai provider outage",
    "review failure spike",
    "bundle storage near quota",
    "cross-tenant access attempt",
)

REQUIRED_RUNBOOKS = (
    "scanner queue stalled",
    "ai provider outage",
    "bundle storage full",
    "github app outage",
    "rollback scanner ruleset",
    "rollback prompt version",
)

REQUIRED_KILL_SWITCHES = (
    "ai explanations",
    "scanner rule packs",
    "prompt versions",
    "new workers",
)

REQUIRED_BACKUP_RECOVERY = (
    "backup cadence",
    "bundle storage restore",
    "evidence hash verification",
    "manual restore smoke test",
    "manual recovery path",
)

REQUIRED_TRUST_CONTROLS = (
    "data retention policy",
    "upload consent event",
    "scanner execution policy",
    "no default active external scanning",
    "exportable review packet",
    "audit log",
    "model/ai limitations",
    "storage region",
    "ai inference provider/region path",
)

REQUIRED_ROLLBACK_PATHS = (
    "scanner ruleset rollback",
    "prompt version rollback",
    "worker image rollback",
)


@dataclass(frozen=True)
class ProductionReadinessCheck:
    name: str
    status: str
    missing: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProductionReadinessResult:
    status: str
    checks: tuple[ProductionReadinessCheck, ...]


def validate_production_readiness_controls(doc_path: Path) -> ProductionReadinessResult:
    if not doc_path.exists():
        check = ProductionReadinessCheck(
            name="production readiness controls document",
            status=STATUS_FAIL,
            missing=(str(doc_path),),
        )
        return ProductionReadinessResult(status=STATUS_FAIL, checks=(check,))
    text = _normalized_text(doc_path)
    checks = (
        _require_all("alerts", REQUIRED_ALERTS, text),
        _require_all("runbooks", REQUIRED_RUNBOOKS, text),
        _require_all("kill switches", REQUIRED_KILL_SWITCHES, text),
        _require_all("backup and recovery", REQUIRED_BACKUP_RECOVERY, text),
        _require_all("customer trust controls", REQUIRED_TRUST_CONTROLS, text),
        _require_all("rollback paths", REQUIRED_ROLLBACK_PATHS, text),
    )
    status = STATUS_PASS if all(check.status == STATUS_PASS for check in checks) else STATUS_FAIL
    return ProductionReadinessResult(status=status, checks=checks)


def _require_all(
    name: str,
    required: tuple[str, ...],
    text: str,
) -> ProductionReadinessCheck:
    missing = tuple(item for item in required if item not in text)
    return ProductionReadinessCheck(
        name=name,
        status=STATUS_PASS if not missing else STATUS_FAIL,
        missing=missing,
    )


def _normalized_text(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").casefold().split())
